const LIBSQLITE_PATH: string = '/usr/lib/libsqlite3.dylib'

const sqlite3_expanded_sql = new NativeFunction(
    Module.getExportByName(LIBSQLITE_PATH, 'sqlite3_expanded_sql'),
    'pointer',          // pStmt
    ['pointer']
);

Interceptor.attach(Module.getExportByName(LIBSQLITE_PATH, 'sqlite3_finalize'), {
    onEnter(args): void {
        const query: string = sqlite3_expanded_sql(args[0]).readUtf8String()!;
        if (! query.startsWith("SELECT"))
            console.log(sqlite3_expanded_sql(args[0]).readUtf8String());
    }
});