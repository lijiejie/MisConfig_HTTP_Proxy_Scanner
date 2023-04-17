import asyncio
import random
import re
import string
import git .asyncresolver
import wx
import httpx
import lib.common
from lib.common import show_log, VulEvent, user_agent


domain_queue = asyncio.queues.Queue()
total_num_of_domains = None
port_scan_queue = asyncio.queues.Queue()
total_num_of_port_scan = None
open_port_queue = asyncio.queues.Queue()
open_port_domain_queue = asyncio.queues.Queue()
lock = asyncio.Lock()
pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
pattern_title = re.compile(r'.*?<title>(.*?)</title>.*', re.IGNORECASE)
all_targets = set()
ip_port_reported_count = {}
false_positives = []

num_of_working_threads = [0]


async def do_resolve_thread(app):
    resolver = dns.asyncresolver.Resolver()
    while domain_queue.qsize() > 0 and not app.STOP_ME:
        try:
            domain = domain_queue.get_nowait()
            answers = await resolver.resolve(domain, 'A', lifetime=15)
            for answer in answers:
                async with lock:
                    lib.common.targets.add(answer.address)
        except Exception as e:
            pass


async def do_resolve(app):
    lib.common.targets.clear()
    for item in all_targets:
        if pattern_ip.match(item):
            lib.common.targets.add(item)
        else:
            await domain_queue.put(item)
    tasks = []
    for _ in range(min(200, domain_queue.qsize())):
        task = do_resolve_thread(app)
        tasks.append(task)
    await asyncio.gather(*tasks)


async def is_port_open(host, port):
    if not port:
        return True
    try:
        fut = asyncio.open_connection(host, int(port))
        reader, writer = await asyncio.wait_for(fut, timeout=3)
        writer.close()
        try:
            await writer.wait_closed()    # application data after close notify (_ssl.c:2730)
        except Exception as e:
            pass
        await open_port_queue.put((host, int(port), 0))    # mode 0 means needs to fetch default page info
        return True
    except Exception as e:
        return False


async def do_port_scan_thread(app):
    while port_scan_queue.qsize() > 0 and not app.STOP_ME:
        try:
            ip, port = port_scan_queue.get_nowait()
            await is_port_open(ip, port)
        except Exception as e:
            pass


async def do_port_scan(app):
    ports = app.panel_settings.txt_ports.GetValue().replace('，', ',').strip(',').strip().split(',')
    for ip in lib.common.targets:
        for port in ports:
            await port_scan_queue.put((ip, port))
    tasks = []
    num_of_threads = 1000
    for _ in range(num_of_threads):
        task = do_port_scan_thread(app)
        tasks.append(task)
    await asyncio.gather(*tasks)


async def do_proxy_scan(app):
    tasks = []
    task = task_enter_queue_thread(app)
    tasks.append(task)
    num_of_threads = int(app.panel_settings.txt_threads.GetValue())
    for _ in range(num_of_threads):
        task = do_proxy_scan_thread(app)
        tasks.append(task)
    await asyncio.gather(*tasks)


async def task_enter_queue_thread(app):
    counter = 0
    while not app.STOP_ME:
        while open_port_domain_queue.qsize() > 10000:
            await asyncio.sleep(0.001)

        if open_port_queue.qsize() == 0 and open_port_domain_queue.qsize() == 0 and num_of_working_threads[0] == 0:
            if counter > 10:
                break
            else:
                await asyncio.sleep(0.05)
                counter += 1
                continue
        try:
            ip, port, mode = open_port_queue.get_nowait()
        except Exception as e:
            await asyncio.sleep(0.001)
            continue
        if mode == 0:
            await open_port_domain_queue.put((ip, port, lib.common.domains_to_test[0]))
        else:
            for domain in lib.common.domains_to_test:
                await open_port_domain_queue.put((ip, port, domain))


async def do_proxy_scan_thread(app):
    wait_count = 0
    while not app.STOP_ME:
        try:
            ip, port, domain = open_port_domain_queue.get_nowait()
            wait_count = 0
        except:
            await asyncio.sleep(0.1)
            if open_port_queue.qsize() == 0 and open_port_domain_queue.qsize() == 0 and num_of_working_threads[0] == 0:
                wait_count += 1
                if wait_count > 5:
                    break
            continue
        async with lock:
            num_of_working_threads[0] += 1
        try:
            target = '%s_%s' % (ip, port)
            if target not in lib.common.not_existed_domain_page_info:
                await check_default_page_info(ip, port, domain)
                continue
            info = lib.common.not_existed_domain_page_info[target]
            headers = {'User-Agent': user_agent, 'Range': 'bytes=0-2048000', 'Host': domain}

            url = '%s://%s:%s' % (info['protocol'], ip, port)
            async with httpx.AsyncClient(verify=False) as client:
                r = await client.get(url, headers=headers, timeout=30)

            if r.status_code != info['status_code'] or \
                abs(int(r.headers.get('Content-Length', 0)) - info['content_length']) > 100:
                if '%s_%s' % (ip, port) not in ip_port_reported_count:
                    ip_port_reported_count[target] = 1
                else:
                    ip_port_reported_count[target] += 1
                if ip_port_reported_count[target] < 1000:
                    m = pattern_title.match(r.text)
                    title = m.group(1).strip() if m else r.text[:200].replace('\r', '').replace('\n', '')
                    show_log('[Vul] %s://%s:%s %s %s' % (info['protocol'], ip, port, domain, title))
                    vul = (info['protocol'], ip + ':' + str(port), domain, str(r.status_code), title)
                    wx.PostEvent(lib.common.REF_FRAME, VulEvent(vul=vul))
                else:
                    if target not in false_positives:
                        false_positives.append(target)
                        show_log('Over 1000 vulnerabilities reported, marked as false positive: %s:%s' % (ip, port))

        except Exception as e:
            pass
        finally:
            async with lock:
                num_of_working_threads[0] -= 1


async def check_default_page_info(ip, port, domain):
    try:
        random_prefix = ''.join(random.choices(string.ascii_letters, k=5))
        headers = {'User-Agent': user_agent, 'Host': random_prefix + domain, 'Range': 'bytes=0-2048000'}
        if port == 443:
            url = 'https://%s:%s' % (ip, port)
        else:
            url = 'http://%s:%s' % (ip, port)
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(url, headers=headers, timeout=30)
        if r.status_code == 400 and r.text.find('The plain HTTP request was sent to HTTPS port'):
            url = 'https://%s:%s' % (ip, port)
            async with httpx.AsyncClient(verify=False) as client:
                r = await client.get(url, headers=headers)

        async with lock:
            lib.common.not_existed_domain_page_info['%s_%s' % (ip, port)] = \
                {'protocol': url.split('://')[0],
                 'status_code': r.status_code,
                 'content_length': int(r.headers.get('Content-Length', 0))
                 }
        await open_port_queue.put((ip, int(port), 1))    # now we're ready to do the rest tests
    except Exception as e:
        pass


def scan(app):
    all_targets.clear()
    false_positives.clear()
    lib.common.not_existed_domain_page_info = {}
    targets = app.panel_targets_input.txt_domain_ips.GetValue()

    # clear all queues, in case some old items still in queue
    for q in [domain_queue, port_scan_queue, open_port_queue, open_port_domain_queue]:
        while q.qsize() > 0:
            q.get_nowait()

    for line in targets.split():
        line = line.replace(',', ' ')
        for item in line.split():
            if item not in all_targets:
                all_targets.add(item)
    if len(all_targets) == 0:
        show_log('No valid targets')
        app.scan_stop(user_aborted=False)
        wx.MessageDialog(lib.common.REF_FRAME, 'No valid targets found. Please check your input',
                         'MisConfig HTTP Proxy Scanner', wx.ICON_INFORMATION).ShowModal()
    else:
        loop = asyncio.new_event_loop()
        loop.run_until_complete(do_resolve(app))
        if not app.STOP_ME:
            show_log('[%s] targets found, start port scanning' % len(lib.common.targets))
        loop.run_until_complete(do_port_scan(app))
        if not app.STOP_ME:
            show_log('[%s] open ports found, around [%s] http requests will be sent' %
                     (open_port_queue.qsize(),
                      open_port_queue.qsize() + open_port_queue.qsize() * app.get_domains_count()))
        loop.run_until_complete(do_proxy_scan(app))
        app.scan_stop(user_aborted=False)
        if not app.STOP_ME:
            show_log('Scan task finished.')
