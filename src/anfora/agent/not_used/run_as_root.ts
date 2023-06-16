/*
 * How to run it? frida -U -f '/bin/sh' -l run_as_root.ts
 */

const system = new NativeFunction(
    Module.getExportByName(null, 'system'), 'int', ['pointer']
);

function sh(cmd: string): number {
  return system(Memory.allocUtf8String(cmd)) as number;
}

sh("snaputil -c 'anfora' '/var'");