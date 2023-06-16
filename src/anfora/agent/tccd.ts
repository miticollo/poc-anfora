/*
 * tccd is an iOS daemon that saves permissions (e.g., popups that ask "... Would
 * Like to Access the Camera") of third-party apps.
 * It stores the permission in an SQLCipher DB: /private/var/mobile/Library/TCC/.
 * This agent prints all INSERT queries that tccd does.
 *
 * To use it run
 *   frida -U -n 'tccd' -l agent.ts
 */

const LIBSQLITE_PATH: string = '/usr/lib/libsqlite3.dylib'

let stmt: NativePointer | undefined;
const sqlQuery: (string | number | null)[] = [];

const sqlite3_expanded_sql = new NativeFunction(
    Module.getExportByName(LIBSQLITE_PATH, 'sqlite3_expanded_sql'),
    'pointer',          // pStmt
    ['pointer']
);

Interceptor.attach(Module.getExportByName(LIBSQLITE_PATH, 'sqlite3_prepare_v2'), {
    onEnter(args): void {
        if (args[1].readUtf8String()?.startsWith("INSERT")) {
            if (sqlQuery.length != 0) throw new Error("sqlQuery is not empty!");
            this.ppStmt = args[3];
        }
    },
    onLeave(): void {
        if (this.ppStmt !== undefined) {
            stmt = this.ppStmt.readPointer()
            if (stmt?.isNull()) throw new Error("There is an error in sqlite3_prepare_v2!");
        }
    }
});

Interceptor.attach(Module.getExportByName(LIBSQLITE_PATH, 'sqlite3_bind_text'), {
    onEnter(args): void {
        if (stmt?.equals(args[0])) sqlQuery[args[1].toInt32() - 1] = args[2].readUtf8String();
    }
});

Interceptor.attach(Module.getExportByName(LIBSQLITE_PATH, 'sqlite3_bind_int'), {
    onEnter(args): void {
        if (stmt?.equals(args[0])) sqlQuery[args[1].toInt32() - 1] = args[2].toInt32();
    }
});

Interceptor.attach(Module.getExportByName(LIBSQLITE_PATH, 'sqlite3_bind_int64'), {
    onEnter(args): void {
        if (stmt?.equals(args[0])) sqlQuery[args[1].toInt32() - 1] = int64(args[2].toString()).toNumber();
    }
});

Interceptor.attach(Module.getExportByName(LIBSQLITE_PATH, 'sqlite3_bind_null'), {
    onEnter(args): void {
        if (stmt?.equals(args[0])) sqlQuery[args[1].toInt32() - 1] = null;
    }
});

Interceptor.attach(Module.getExportByName(LIBSQLITE_PATH, 'sqlite3_finalize'), {
    onEnter(args): void {
        if (stmt?.equals(args[0])) {
            send({
                type: "tccd",
                query: sqlQuery,
                expandedQuery: sqlite3_expanded_sql(stmt).readUtf8String(),
                pid: getPidForApplication(<string>sqlQuery[1])
            });
            sqlQuery.length = 0;
            stmt = undefined;
        }
    }
});

function getPidForApplication(bundleID: string): number {
    // https://github.com/frida/frida-core/blob/53d3724dd7/src/darwin/springboard.h#L24-L46
    const {FBSSystemService} = ObjC.classes;
    // https://github.com/frida/frida-core/blob/53d3724dd7/src/darwin/frida-helper-backend-glue.m#L1369-L1371
    const service = FBSSystemService.sharedService();
    return service.pidForApplication_(bundleID);
}