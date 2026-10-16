#!/usr/bin/env python3
"""Optional KSNI, notification and JobView integration test (no radio or graphical display).

cargo build --workspace --locked
dbus-run-session -- python3 crates/airdrop/tests/desktop_notifications.py
Requires Python PyGObject/Gio and a default tray-ksni debug build.
"""
import concurrent.futures
import json
import os
import pathlib
import plistlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid

from gi.repository import Gio, GLib

ROOT = pathlib.Path(__file__).resolve().parents[3]
context = GLib.MainContext.default()
bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
notices, history = {}, []
next_id = 1
xml = '''<node><interface name="org.freedesktop.Notifications">
<method name="GetCapabilities"><arg type="as" direction="out"/></method>
<method name="Notify"><arg type="s" direction="in"/><arg type="u" direction="in"/>
<arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="s" direction="in"/>
<arg type="as" direction="in"/><arg type="a{sv}" direction="in"/><arg type="i" direction="in"/>
<arg type="u" direction="out"/></method>
<method name="CloseNotification"><arg type="u" direction="in"/></method>
<signal name="ActionInvoked"><arg type="u"/><arg type="s"/></signal>
<signal name="NotificationClosed"><arg type="u"/><arg type="u"/></signal>
</interface></node>'''
PATH = '/org/freedesktop/Notifications'
IFACE = 'org.freedesktop.Notifications'

def signal(name, value):
    bus.emit_signal(None, PATH, IFACE, name, value)
    bus.flush_sync(None)

def method(_conn, _sender, _path, _iface, name, args, invocation):
    global next_id
    values = args.unpack()
    if name == 'GetCapabilities':
        invocation.return_value(GLib.Variant('(as)', (['actions', 'body', 'body-markup', 'persistence'],)))
    elif name == 'Notify':
        _, replaces, _, summary, body, actions, hints, timeout = values
        id = replaces or next_id
        if not replaces: next_id += 1
        notice = dict(id=id, replaces=replaces, summary=summary, body=body, actions=actions, hints=hints, timeout=timeout)
        notices[id] = notice
        history.append(notice)
        invocation.return_value(GLib.Variant('(u)', (id,)))
    else:
        notices.pop(values[0], None)
        invocation.return_value(None)
        signal('NotificationClosed', GLib.Variant('(uu)', (values[0], 3)))

bus.register_object(PATH, Gio.DBusNodeInfo.new_for_xml(xml).interfaces[0], method, None, None)
bus.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'RequestName', GLib.Variant('(su)', (IFACE, 0)), None, Gio.DBusCallFlags.NONE, 3000, None)

def wait(predicate, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        while context.pending(): context.iteration(False)
        result = predicate()
        if result: return result
        time.sleep(.015)
    raise AssertionError('timed out')

def popup(subject, action):
    return next((n for n in notices.values() if subject in n['body'] and action in n['actions']), None)

def click(notice, action):
    signal('ActionInvoked', GLib.Variant('(us)', (notice['id'], action)))

with tempfile.TemporaryDirectory(prefix='owl-notifications-') as tmp:
    tmp = pathlib.Path(tmp)
    run, output = tmp / 'run', tmp / 'received'
    with socket.socket(socket.AF_INET6) as listener:
        listener.bind(('::1', 0))
        port = listener.getsockname()[1]
    env = dict(os.environ)
    env.pop('DISPLAY', None)
    env.pop('WAYLAND_DISPLAY', None)
    env['GDK_BACKEND'] = 'x11'
    env['NO_AT_BRIDGE'] = '1'
    log = (tmp / 'daemon.log').open('w+')
    daemon = subprocess.Popen([str(ROOT / 'target/debug/airdropd'), '--no-radio', '--no-bluetooth', '--listen', f'[::1]:{port}', '--run-dir', str(run), '--keys', str(tmp / 'keys'), '--output', str(output), '--duration', '90', '--approval-timeout', '10', '--completion-grace', '30'], env=env, stdout=log, stderr=log)
    clients = []
    passed = False
    def control(command):
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(3)
            stream.connect(str(run / 'control.sock'))
            stream.sendall(json.dumps(command).encode() + b'\n')
            reply = json.loads(stream.makefile('rb').readline())
            assert 'ok' in reply, reply
            return reply['ok']
    def cli(*args):
        client = subprocess.Popen([str(ROOT / 'target/debug/catdrop'), *args, '--run-dir', str(run)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        clients.append(client)
        return client
    def finish(client, success):
        wait(lambda: client.poll() is not None)
        stdout, stderr = client.communicate()
        assert (client.returncode == 0) == success, (stdout, stderr)
    def send(label):
        return cli('send', 'fixture', '--direct', f'[::1]:{port}', '--url', f'https://example.com/{label}')
    try:
        wait(lambda: (run / 'control.sock').exists())
        contacts = str(tmp / 'contacts')
        finish(cli('contact', '--contacts-file', contacts, 'add', 'Test@Example.com'), True)
        def contact_list():
            return control({'command': 'contact', 'action': {'action': 'list'}, 'contacts_file': contacts})
        assert contact_list() == ['test@example.com']
        finish(cli('contact', '--contacts-file', contacts, 'remove', 'test@example.com'), True)
        assert contact_list() == []
        # Exercise the default tray over D-Bus without GTK or a display server.
        def tray_name():
            names = bus.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus',
                'org.freedesktop.DBus', 'ListNames', None, None,
                Gio.DBusCallFlags.NONE, 3000, None).unpack()[0]
            return next((n for n in names if n.startswith(f'org.kde.StatusNotifierItem-{daemon.pid}-')), None)
        tray = wait(tray_name)
        def menu_call(method, args):
            return bus.call_sync(tray, '/MenuBar', 'com.canonical.dbusmenu',
                method, args, None, Gio.DBusCallFlags.NONE, 3000, None)
        def menu():
            _, layout = menu_call('GetLayout', GLib.Variant('(iias)', (0, -1, []))).unpack()
            return {props.get('label'): (id, props) for id, props, children in layout[2]}
        def tray_click(label):
            id, _ = menu()[label]
            menu_call('Event', GLib.Variant('(isvu)', (id, 'clicked', GLib.Variant('i', 0), 0)))
        def selected(label):
            items = menu()
            return all(items.get(name, (0, {}))[1].get('toggle-state') == int(name == label)
                for name in ['Receiving off', 'Contacts only', 'Everyone'])
        wait(lambda: selected('Receiving off'))
        control({'command': 'discoverable', 'mode': 'everyone'})
        wait(lambda: selected('Everyone'))
        tray_click('Receiving off')
        wait(lambda: control({'command': 'status'})['visibility'] == 'off')
        wait(lambda: selected('Receiving off'))
        tray_click('Everyone')
        wait(lambda: control({'command': 'status'})['visibility'] == 'everyone')
        wait(lambda: selected('Everyone'))
        for label, action, success in [('approved', 'accept', True), ('declined', 'decline', False), ('cli-race', 'accept', True), ('out-cancel', 'cancel', False)]:
            client = send(label)
            incoming = wait(lambda: popup(label, 'accept'))
            status = control({'command': 'status'})
            session_id = status['session']['id']
            if label == 'cli-race':
                pending = next(t for t in status['transfers'] if t['state'] == 'pending')
                finish(cli('accept', pending['offer']['id']), True)
                click(incoming, 'decline')  # A stale button must not undo CLI approval.
            elif action == 'cancel':
                outgoing = wait(lambda: next((n for n in notices.values() if label in n['body'] and n['summary'].startswith('AirDrop to') and 'cancel' in n['actions']), None))
                click(outgoing, 'cancel')
            else:
                click(incoming, action)
            finish(client, success)
            wait(lambda: any(label in n['body'] and not n['actions'] for n in notices.values()))
            assert control({'command': 'status'})['session']['id'] == session_id
        # Exercise CLI cancellation by outgoing ID while a notification is pending.
        client = send('cli-cancel')
        wait(lambda: popup('cli-cancel', 'accept'))
        outgoing = next(t for t in control({'command': 'status'})['outgoing'] if t['state'] == 'pending')
        finish(cli('cancel', outgoing['id']), True)
        finish(client, False)

        path = tmp / 'outgoing.bin'
        path.write_bytes(os.urandom(2 * 1024 * 1024))
        client = cli('send', 'fixture', str(path), '--direct', f'[::1]:{port}')
        click(wait(lambda: popup('outgoing.bin', 'accept')), 'accept')
        finish(client, True)
        sent = next(t for t in control({'command': 'status'})['outgoing'] if t['items'] == ['outgoing.bin'])
        assert sent['state'] == 'completed' and sent['bytes'] == sent['total_bytes'] > 0
        wait(lambda: any(n['summary'] == 'AirDrop sent' and 'outgoing.bin' in n['body'] and n['hints'].get('value') == 100 for n in notices.values()))

        def raw_transfer(name, proceed, half_sent, cancel):
            payload = os.urandom(256 * 1024)
            cpio = bytearray()
            def member(name, data):
                cpio.extend(b'070701')
                for value in [1, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name) + 1, 0]:
                    cpio.extend(f'{value:08x}'.encode())
                cpio.extend(name.encode() + b'\0')
                cpio.extend(b'\0' * (-len(cpio) % 4))
                cpio.extend(data)
                cpio.extend(b'\0' * (-len(cpio) % 4))
            member(name, payload)
            member('TRAILER!!!', b'')
            wire = b''.join((len(chunk) | 0x80000000).to_bytes(4, 'big') + chunk for chunk in [cpio[i:i+65536] for i in range(0, len(cpio), 65536)])
            id = str(uuid.uuid4()).upper()
            offer = plistlib.dumps({'TransferID': id, 'SenderComputerName': 'Test <phone>', 'Files': [{'FileName': name, 'FileSize': len(payload)}]}, fmt=plistlib.FMT_BINARY)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(('::1', port), timeout=8) as tcp:
                with context.wrap_socket(tcp, server_hostname='AirDrop') as tls:
                    reader = tls.makefile('rb')
                    def reply():
                        status = reader.readline()
                        length = 0
                        while True:
                            line = reader.readline()
                            if line in (b'\r\n', b''): break
                            if line.lower().startswith(b'content-length:'): length = int(line.split(b':')[1])
                        reader.read(length)
                        return status
                    tls.sendall(f'POST /Ask HTTP/1.1\r\nHost: AirDrop\r\nContent-Length: {len(offer)}\r\n\r\n'.encode() + offer)
                    assert b'200' in reply()
                    tls.sendall(f'POST /Upload HTTP/1.1\r\nHost: AirDrop\r\nTransferID: {id}\r\nContent-Type: application/x-dvzip\r\nContent-Length: {len(wire)}\r\n\r\n'.encode() + wire[:len(wire)//2])
                    half_sent.set()
                    assert proceed.wait(8)
                    if cancel:
                        try:
                            assert b'200' not in reply()
                            assert reader.read() == b''
                        except ssl.SSLError: pass
                        return
                    tls.sendall(wire[len(wire)//2:])
                    assert b'200' in reply()

        with concurrent.futures.ThreadPoolExecutor() as pool:
            for cancel in [False, True]:
                name = 'cancel.bin' if cancel else 'complete<&>.bin'
                proceed, half = threading.Event(), threading.Event()
                future = pool.submit(raw_transfer, name, proceed, half, cancel)
                incoming = wait(lambda: popup('cancel.bin' if cancel else 'complete&lt;&amp;&gt;.bin', 'accept'))
                click(incoming, 'accept')
                wait(half.is_set)
                progress = wait(lambda: next((n for n in notices.values() if n['summary'].startswith('Receiving from') and n['hints'].get('value') == 50 and ('cancel.bin' if cancel else 'complete&lt;&amp;&gt;.bin') in n['body']), None))
                assert progress['replaces'] == incoming['id'], 'progress did not replace offer'
                if cancel:
                    click(progress, 'cancel')
                else:
                    signal('NotificationClosed', GLib.Variant('(uu)', (progress['id'], 2)))
                    notices.pop(progress['id'], None)
                    before = len(history)
                    # Run the event loop for multiple progress refreshes after dismissal.
                    until = time.monotonic() + .7
                    wait(lambda: time.monotonic() >= until)
                    assert len(history) == before, 'dismissed progress reopened'
                proceed.set()
                wait(future.done)
                future.result()
                if not cancel:
                    wait(lambda: any(n['summary'] == 'AirDrop received' and 'complete&lt;&amp;&gt;.bin' in n['body'] and n['hints'].get('value') == 100 for n in notices.values()))
                assert control({'command': 'status'})['session']['id'] == session_id
        # Publish JobView after the notification-only scenarios to exercise
        # discovery, approval handoff, progress, cancellation and service failure.
        jobs = {}
        job_interface = 'org.kde.JobViewV2'
        job_xml = '<node><interface name="org.kde.JobViewV2">'
        for method_name, signature in [
            ('setInfoMessage', 's'), ('setTotalAmount', 'ts'),
            ('setProcessedAmount', 'ts'), ('setPercent', 'u'), ('terminate', 's'),
            ('setDescriptionField', 'uss'),
        ]:
            job_xml += f'<method name="{method_name}">'
            job_xml += ''.join(f'<arg type="{t}" direction="in"/>' for t in signature)
            if method_name == 'setDescriptionField':
                job_xml += '<arg type="b" direction="out"/>'
            job_xml += '</method>'
        job_xml += '<signal name="cancelRequested"/></interface></node>'
        job_info = Gio.DBusNodeInfo.new_for_xml(job_xml).interfaces[0]
        def job_method(_conn, _sender, path, _iface, name, args, invocation):
            job = jobs[path]
            if job.get('broken'):
                invocation.return_dbus_error('org.freedesktop.DBus.Error.UnknownObject', 'Job disappeared')
                return
            job[name] = args.unpack()
            invocation.return_value(GLib.Variant('(b)', (True,)) if name == 'setDescriptionField' else None)
        def request_job(_conn, _sender, _path, _iface, _name, args, invocation):
            assert args.unpack() == ('AirDrop', 'folder-download', 1)
            path = f'/JobViewServer/Job{len(jobs) + 1}'
            jobs[path] = {'path': path}
            bus.register_object(path, job_info, job_method, None, None)
            invocation.return_value(GLib.Variant('(o)', (path,)))
        server_xml = '<node><interface name="org.kde.JobViewServer"><method name="requestView"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="i" direction="in"/><arg type="o" direction="out"/></method></interface></node>'
        bus.register_object('/JobViewServer', Gio.DBusNodeInfo.new_for_xml(server_xml).interfaces[0], request_job, None, None)
        bus.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'RequestName', GLib.Variant('(su)', ('org.kde.JobViewServer', 0)), None, Gio.DBusCallFlags.NONE, 3000, None)
        def job_for(label):
            return next((j for j in jobs.values() if label in j.get('setDescriptionField', ('', '', ''))[2]), None)
        def cancel_job(job):
            bus.emit_signal(None, job['path'], job_interface, 'cancelRequested', None)
            bus.flush_sync(None)
        client = send('job-out-cancel')
        wait(lambda: popup('job-out-cancel', 'accept'))
        job = wait(lambda: job_for('job-out-cancel'))
        cancel_job(job)
        finish(client, False)
        wait(lambda: job.get('terminate'))
        assert job['terminate'][0]
        with concurrent.futures.ThreadPoolExecutor() as pool:
            for mode in ['complete', 'cancel', 'fallback']:
                name = f'job-{mode}.bin'
                proceed, half = threading.Event(), threading.Event()
                future = pool.submit(raw_transfer, name, proceed, half, mode != 'complete')
                incoming = wait(lambda: popup(name, 'accept'))
                assert job_for(name) is None
                click(incoming, 'accept')
                wait(half.is_set)
                job = wait(lambda: job_for(name))
                wait(lambda: job.get('setPercent') == (50,))
                assert job['setProcessedAmount'][0] > 0
                assert job['setTotalAmount'][0] > job['setProcessedAmount'][0]
                wait(lambda: incoming['id'] not in notices)
                assert not popup(name, 'cancel'), 'duplicate progress notification'
                if mode == 'fallback':
                    job['broken'] = True
                    click(wait(lambda: popup(name, 'cancel')), 'cancel')
                elif mode == 'cancel':
                    cancel_job(job)
                proceed.set()
                wait(future.done)
                future.result()
                if mode != 'fallback':
                    wait(lambda: job.get('terminate'))
                    assert bool(job['terminate'][0]) == (mode == 'cancel')
                if mode == 'complete':
                    assert job['setPercent'] == (100,)
                    assert not any(name in n['body'] and not n['actions'] for n in notices.values())
        client = send('job-shutdown')
        shutdown_job = wait(lambda: job_for('job-shutdown'))
        tray_click('Quit AirDrop')
        wait(lambda: daemon.poll() is not None)
        assert daemon.returncode == 0
        wait(lambda: shutdown_job.get('terminate'))
        wait(lambda: not notices)
        passed = True
        print('PASS: KSNI menu/CLI synchronization and Quit, notification approvals, decline, stale action/CLI race, outgoing cancel, CLI cancel, incoming progress/cancel, escaped text, dismissal, completion, JobView progress/cancel/fallback, shutdown')
    finally:
        for client in clients:
            if client.poll() is None:
                client.terminate()
                client.wait(timeout=5)
        if daemon.poll() is None:
            daemon.terminate()
            daemon.wait(timeout=5)
        if not passed:
            log.seek(0)
            print(log.read())
