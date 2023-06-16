import logging
import pathlib
import sys
import threading

import frida
from frida.core import Device, ScriptMessage

from main import WDA_CF_BUNDLE_NAME

PREFIXES = ("/var/containers/Bundle/Application/",
            "/Applications/",
            "/private/var/containers/Bundle/Application/",
            "/System/Library/Frameworks/")

AGENT_ROOT_PATH: str = str(pathlib.Path(__file__).parent / 'agent')

logger = logging.getLogger(__name__)


def spawn_thread_closure(device: Device, stop_event: threading.Event):
    import _frida

    from frida.core import Session, Script, ScriptExportsSync
    from anfora.anfora import detect_analysis_paths, report_query_on_tcc_db, report_contact_crud_op, garbage, \
        report_new_notification_permission, report_change_on_ne_configuration

    from typing import List, Tuple

    def on_message(process: _frida.Process, message: ScriptMessage):
        if message["type"] == "send":
            payload: dict = message["payload"]
            mtype: str = payload["type"]
            if mtype == "contact":
                report_contact_crud_op(process, payload['message'])
            elif mtype == "location":
                # TODO: handle location
                #  CoreLocationVanillaWhenInUseAuthPromptPlugin
                pass
        else:
            logger.critical(f"Unhandled message: {message} in {process}")

    def on_spawned(spawn: _frida.Spawn):
        processes_by_pid = device.enumerate_processes([spawn.pid], scope='full')
        if len(processes_by_pid) != 1:
            logger.warning(f'{processes_by_pid} for PID {spawn.pid}')
            # you can ignore this warning, but you will lose data
            device.resume(spawn.pid)
        else:
            process: _frida.Process = processes_by_pid[0]
            if any(process.parameters['path'].startswith(prefix) for prefix in PREFIXES):
                # this spawned process is interesting
                pending.append((process, spawn))
                event.set()
            else:
                device.resume(spawn.pid)

    def tccd():
        def _on_message(message: ScriptMessage, data):
            if message["type"] == "send":
                payload: dict = message["payload"]
                if payload["pid"] != -1:
                    process: _frida.Process = device.enumerate_processes(pids=[payload["pid"]])[0]
                    report_query_on_tcc_db(process, payload['query'])
                else:
                    logger.warning(f"[TCC] Skipping client {payload['query'][1]}")
            else:
                logger.critical(f"[TCC] Unhandled message: {message}")

        bundle: str = compiler.build('tccd.ts', project_root=AGENT_ROOT_PATH, compression='terser')
        session: Session = device.attach('tccd')
        sessions.append(session)
        script: Script = session.create_script(source=bundle)
        script.on("message", _on_message)
        script.load()

    def bulletinBoard():
        def _on_message(message: ScriptMessage, data):
            if message["type"] == "send":
                payload: dict = message["payload"]
                if payload["pid"] != -1:
                    process: _frida.Process = device.enumerate_processes(pids=[payload["pid"]])[0]
                    report_new_notification_permission(process, payload['BBSectionInfoSettings'])
                else:
                    logger.warning(f"[BulletinBoard] Skipping app {payload['appName']}")
            else:
                logger.critical(f"[BB] Unhandled message: {message}")

        session: Session = device.attach('SpringBoard')
        sessions.append(session)
        script: Script = session.create_script(source="""\
Interceptor.attach(ObjC.classes.BBServer['- _setSectionInfo:forSectionID:'].implementation, {
    onEnter(args) {
        const bbSectionInfo = new ObjC.Object(args[2]);
        send({
            type: "BulletinBoard",
            appName: bbSectionInfo['- appName']().toString(),
            BBSectionInfoSettings: bbSectionInfo['- sectionInfoSettings']().toString(),
            pid: ObjC.classes.FBSSystemService.sharedService().pidForApplication_((new ObjC.Object(args[3])).toString()),
        });
    }
});""")
        script.on("message", _on_message)
        script.load()

    def nehelper():
        def _on_message(message: ScriptMessage, data):
            if message["type"] == "send":
                payload: dict = message["payload"]
                report_change_on_ne_configuration(payload["configuration"])
            else:
                logger.critical(f"[NE] Unhandled message: {message}")

        session: Session = device.attach('nehelper')
        sessions.append(session)
        script: Script = session.create_script(source="""\
Interceptor.attach(ObjC.classes.NEConfigurationManager['- saveConfigurationToDisk:currentSignature:userUUID:isUpgrade:completionQueue:completionHandler:'].implementation, {
    onEnter(args) {
        const description = (new ObjC.Object(args[2])).toString();
        const json = description
            // TODO: ugly converter. Which fields are important?
            .replace(/(?<![{(},])$(?!\s+[}])/gm, `,`)
            .replace(/,(?=$\s+\))/gm, ``)
            .replace(/\(/gm, `[`)
            .replace(/\)/gm, `]`)
            .replace(/YES/gm, `true`)
            .replace(/NO/gm, `false`)
            .replace(/(\S.+)\s+=\s+/gm, `"$1": `)
            .replace(/(?<=: )(?!true|false)([a-zA-Z0-9].+)(?=,)/gm, `"$1"`);
        send({
            type: "nehelper",
            configuration: JSON.parse(json),
        });
    }
});""")
        script.on("message", _on_message)
        script.load()

    def main():
        process: _frida.Process
        spawn: _frida.Spawn

        bundle_for_plugins: str = compiler.build('plugins-3rd-party-index.ts', project_root=AGENT_ROOT_PATH,
                                                 compression='terser')
        bundle: str = compiler.build('index.ts', project_root=AGENT_ROOT_PATH, compression='terser')

        while not stop_event.wait(.1):
            if event.is_set():
                while len(pending) >= 1:
                    process, spawn = pending.pop()
                    if process.name == WDA_CF_BUNDLE_NAME:
                        logger.critical('WDA re-spawned!')
                        sys.exit(1) # This IS NOT a good idea!
                    path: str = process.parameters['path']
                    try:
                        session: Session = device.attach(process.pid, realm="native")
                        # TODO: sessions.append(session). But https://github.com/frida/frida/issues/1056. Why?
                        if 'appex' in path:
                            script: Script = session.create_script(name="plugins-3rd-party-index",
                                                                   source=bundle_for_plugins)
                        else:
                            script: Script = session.create_script(name="index", source=bundle)
                        script.on("message", lambda message, data, proc=process: on_message(proc, message))
                        # load() waits for the script to be fully executed before returning:
                        # https://t.me/fridadotre/84125
                        script.load()
                        device.resume(process.pid)
                        if 'appex' in path and not path.startswith("/System/Library/Frameworks/"):
                            api: ScriptExportsSync = script.exports_sync
                            identifier: str = api.get_identifier(path.split('PlugIns', 1)[0])
                        else:
                            identifier: str = spawn.identifier
                    except _frida.ProcessNotRespondingError as e:
                        logger.warning(
                            f'[FRIDA] {e.__class__.__name__} occurred => {process.name} (PID {process.pid}) skipped!'
                        )
                    if not path.startswith("/System/Library/Frameworks/"):
                        parameters: dict = device.enumerate_applications(identifiers=[identifier], scope='full')[0].parameters
                        if 'containers' in parameters:
                            detect_analysis_paths(process, set(parameters['containers'].values()))
                        else:
                            garbage(process)
                    else:
                        garbage(process)
                event.clear()

        device.disable_spawn_gating()
        stop_event.clear()
        for session in sessions:
            if not session.is_detached:
                session.detach()

    pending: List[Tuple[_frida.Process, _frida.Spawn]] = []
    event: threading.Event = threading.Event()

    device.on('spawn-added', on_spawned)
    device.enable_spawn_gating()

    compiler: frida.Compiler = frida.Compiler()
    compiler.on("diagnostics", lambda diag: logger.critical(f"on_diagnostics: {diag}"))

    sessions: List[Session] = []

    tccd()
    bulletinBoard()
    nehelper()
    main()
