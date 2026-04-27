#include <lua.h>
#include <lauxlib.h>
#include <stdlib.h>
#include <string.h>

static FILE *hook_file = NULL;
static int hook_count = 0;
static const char *outdir = NULL;

static int hook_loadstring(lua_State *L) {
    const char *code = lua_tostring(L, 1);
    if (code && strlen(code) > 5 && hook_file) {
        char path[1024];
        hook_count++;
        snprintf(path, sizeof(path), "%s/layer_%d.lua", outdir, hook_count);
        FILE *f = fopen(path, "w");
        if (f) {
            fwrite(code, 1, strlen(code), f);
            fclose(f);
        }
    }
    lua_pushcfunction(L, hook_loadstring);
    return 1;
}

static int hook_init(lua_State *L) {
    outdir = lua_tostring(L, 1);
    lua_getglobal(L, "loadstring");
    lua_pushcfunction(L, hook_loadstring);
    lua_setglobal(L, "loadstring");
    return 0;
}

int luaopen_hooks(lua_State *L) {
    static const luaL_Reg funcs[] = {
        {"init", hook_init},
        {NULL, NULL}
    };
    luaL_register(L, "hooks", funcs);
    return 1;
}
