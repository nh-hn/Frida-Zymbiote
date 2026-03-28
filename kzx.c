#include <dirent.h>
#include <stdio.h>
#include <bits/ctype_inlines.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/mman.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "stub.h"
#include "elf.h"

#define SymbolName "_Z27android_os_Process_setArgV0P7_JNIEnvP8_jobjectP8_jstring"
typedef struct {
    uintptr_t start;
    uintptr_t end;
    char perms[5];
    char pathname[256];
} map_entry;
int count = 0;
map_entry heap_candidates[64];
typedef struct{
    uintptr_t start;
    uintptr_t end;
    char perms[5];
    char pathname[256];
} targetso;

targetso ts;

typedef struct {
    uintptr_t originAddr;
    uintptr_t origin_art_method_solt;
} Hkctx;
Hkctx hkctx;
//功能函数
volatile sig_atomic_t keep_running = 1;

void signal_handler(int setting) {
    keep_running = 0;
}

//step1:找到zygtoe64的pid,目标app的uid
uid_t get_uid_from_package(const char *package_name) {
    FILE* fp = fopen("/data/system/packages.list","r");
    if (!fp) {
        perror("[-] Failed to open packages.list");
        return -1;
    }

    char line[64];
    while (fgets(line,sizeof(line),fp)) {
        if (strstr(line, package_name) != NULL) {
            char pkg[128];
            uid_t uid;

            if (sscanf(line, "%s %d", pkg, &uid) == 2) {
                if (strcmp(pkg, package_name) == 0) {
                    return uid;
                }
            }
        }
    }
    return -1;
}
pid_t getZygotePid(char* processname){
    DIR* dir = opendir("/proc");
    if(!dir){
        printf("打开/proc失败");
        return -1;
    }
    struct dirent* entry;
    while((entry = readdir(dir)) != NULL){
        if(!isdigit(entry->d_name[0])){ continue;} // 只处理数字开头目录
        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
        FILE* fp = fopen(cmdline_path,"r");
        if(!fp){
            printf("cmdline打开失败");
            continue;
        }
        char cmdline[4096];
        size_t n = fread(cmdline, 1, sizeof(cmdline)-1, fp);
        fclose(fp);

        if (n > 0) {
            cmdline[n] = '\0'; // fread 不会自动加 \0
            // cmdline 是用 '\0' 分隔的参数，所以可以直接查找进程名
//            printf("%s %s \n",cmdline,processname);
            if (strstr(cmdline, processname) != NULL) {
                closedir(dir);
                return (pid_t) atoi(entry->d_name);
            }
        }
    }
    return 0;
}
//setp2:从zygote64进程读出libandroid_runtime基地址,找到setArgV0符号地址,
//收集artmethod存放的可疑maps，找到libstagefright.so的最后一页可执行页，作为跳板空间
int is_heap_candidate(map_entry* m) {
    if (m->perms[0] != 'r' || m->perms[1] != 'w')
        return 0;

    if (m->pathname[0] == '\0')
        return 0;

    if (strstr(m->pathname, "boot.art") ||
        strstr(m->pathname, "boot-framework.art") ||
        strstr(m->pathname, "dalvik-LinearAlloc")) {
        return 1;
    }

    return 0;
}
uintptr_t getheaplist(pid_t zygote_pid,targetso* t){
    char buffer[64];
    sprintf(buffer,"/proc/%d/maps",zygote_pid);
    FILE* fp = fopen(buffer,"r");
    if(!fp){
        printf("maps读取失败 \n");
    }
    char line[512];
    uintptr_t addr_start = 0;

    while(fgets(line,sizeof(line),fp)){
        if(strstr(line,"libstagefright.so")){
            sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]",&t->start, &t->end, t->perms, t->pathname);
            if(t->perms[2] == 'x'){
                ts.start = t->start;ts.end = t->end;
                strcpy(t->perms,t->perms);
                printf("跳板内存区域: %lx-%lx %s %s \n",t->start, t->end, t->perms, t->pathname);
            }
        }
        map_entry m = {0};
        sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]",&m.start, &m.end, m.perms, m.pathname);
        if (is_heap_candidate(&m)) {
            printf("heap candidate: %lx-%lx %s %s \n",m.start, m.end, m.perms, m.pathname);
            heap_candidates[count++] = m;
        }
    }
    fclose(fp);
    return 0;
}
uintptr_t getsobase(char* soname,pid_t zygote_pid){
    char buffer[64];
    sprintf(buffer,"/proc/%d/maps",zygote_pid);
    FILE* fp = fopen(buffer,"r");
    if(!fp){
        printf("maps读取失败 \n");
    }
    char line[512];
    uintptr_t addr_start = 0;
    while(fgets(line,sizeof(line),fp)){
        if (strstr(line, soname)) { // 找到包含 soname 的行
            // 解析起始地址
            sscanf(line, "%lx-", &addr_start);
            fclose(fp);
        }
    }
    return addr_start;
}
//setp3:扫描可疑内存区域列表，找到setArgV0 artmethod enter_point地址
uintptr_t getFnpostion(uintptr_t symbol,pid_t zygote_pid){

    char mempath[64];
    sprintf(mempath,"/proc/%d/mem",zygote_pid);
    int mem_fd = open(mempath,O_RDONLY);
    if(mem_fd < 0){
        printf("打开proc/self/mem错误 \n");
        return 0;
    }

    for (int i = 0; i < count; i++) {
        map_entry* heap = &heap_candidates[i];
        size_t region_size = heap->end - heap->start;
        printf("start: 0x%lx,end: 0x%lx \n",heap->start,heap->end);
        if(region_size < sizeof(uintptr_t)){
            //为什么这么判断 因为artmethod指针大小一定是8字节，小于的话肯定不在这里了
            continue;
        }
        uint8_t* buffer = (uint8_t*)malloc(region_size);
        ssize_t read_size = pread(mem_fd, buffer, region_size, (off_t)(heap->start));
        if (read_size != (ssize_t)(region_size)) {
            continue;
        }
        uint8_t* found = (uint8_t*)(memmem(buffer,region_size, &symbol, sizeof(symbol)));
        if (found != NULL) {
            uintptr_t art_method_slot = heap->start + (uintptr_t)(found - buffer);
            hkctx.origin_art_method_solt = art_method_slot;
            printf("找到art_method_solt: 0x%lx \n",art_method_slot);
            return art_method_slot;
        }
    }
    return 0;
}
uintptr_t getSymbolOffset(const char* so_path, const char* symbol){
    FILE* fp = fopen(so_path,"rb");
    if(!fp){
        return 0;
    }

    // 1. 读取 ELF header
    Elf64_Ehdr ehdr;
    fread(&ehdr, sizeof(ehdr), 1, fp);

    // 2. 读取 section header 表
    Elf64_Shdr* shdr_table = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    fseek(fp, ehdr.e_shoff, SEEK_SET);
    fread(shdr_table, ehdr.e_shentsize, ehdr.e_shnum, fp);

    // 3. 找 section name 表
    Elf64_Shdr shstr = shdr_table[ehdr.e_shstrndx];
    char* shstrtab = malloc(shstr.sh_size);
    fseek(fp, shstr.sh_offset, SEEK_SET);
    fread(shstrtab, shstr.sh_size, 1, fp);

    Elf64_Off dynsymOff = 0, dynstrOff = 0;
    Elf64_Xword dynsymSize = 0, dynstrSize = 0;

    // 4. 找 .dynsym 和 .dynstr
    for (int i = 0; i < ehdr.e_shnum; i++) {
        char* name = shstrtab + shdr_table[i].sh_name;

        if (strcmp(name, ".dynsym") == 0) {
            dynsymOff = shdr_table[i].sh_offset;
            dynsymSize = shdr_table[i].sh_size;
        }

        if (strcmp(name, ".dynstr") == 0) {
            dynstrOff = shdr_table[i].sh_offset;
            dynstrSize = shdr_table[i].sh_size;
        }
    }

    if (!dynsymOff || !dynstrOff) {
        return 0;
    }

    // 5. 读取 dynsym 和 dynstr
    Elf64_Sym* dynsym = malloc(dynsymSize);
    char* dynstr = malloc(dynstrSize);

    fseek(fp, dynsymOff, SEEK_SET);
    fread(dynsym, dynsymSize, 1, fp);

    fseek(fp, dynstrOff, SEEK_SET);
    fread(dynstr, dynstrSize, 1, fp);

    // 6. 查找符号
    for (int i = 0; i < dynsymSize / sizeof(Elf64_Sym); i++) {
        char* name = dynstr + dynsym[i].st_name;

        if (strcmp(name, symbol) == 0) {
            printf("找到对应的符号信息:%s \n",symbol);
            uintptr_t offset = dynsym[i].st_value;

            free(dynsym);
            free(dynstr);
            free(shdr_table);
            free(shstrtab);
            fclose(fp);

            return offset;
        }
    }

    // 清理
    free(dynsym);
    free(dynstr);
    free(shdr_table);
    free(shstrtab);
    fclose(fp);

    return 0;
}



int main(int argc,char* argv[]){

    signal(SIGINT, signal_handler);

    char* package_name = argv[1];
    char* so_path = argv[2];
    //获得zygote pid
    pid_t zygote_pid = getZygotePid("zygote64");
    printf("zygote64 pid: %d \n",zygote_pid);
    kill(zygote_pid, SIGSTOP);
    //获得uid
    uid_t yuid = get_uid_from_package(package_name);
    if(yuid == -1){
        printf("获取uid失败 \n");
    }
    printf("目标app uid: %d \n",yuid);
    //得到libandroid_runtime.so基址，以及构造heap列表，找到跳板内存区域
    targetso t = {0};
    uintptr_t soBase = getsobase("libandroid_runtime.so",zygote_pid);
    if(soBase == 0){
        printf("获取libandroid_runtime.so基地址失败 \n");

    }
    printf("成功获取libandroid_runtime.so基地址: 0x%lx \n",soBase);

    getheaplist(zygote_pid,&t);

    uintptr_t symbol_offset = getSymbolOffset("/system/lib64/libandroid_runtime.so",SymbolName);
    uintptr_t symbol_offset_shdr = getSymbolOffset("/system/lib64/libandroid_runtime.so",SymbolName);
    printf("偏移: 0x%lx symbol_offset_shdr: 0x%lx \n",symbol_offset,symbol_offset_shdr);
    uintptr_t symbol_addr = soBase + symbol_offset;
    printf("符号地址为: 0x%lx \n",symbol_addr);
    hkctx.originAddr = symbol_addr;
    uintptr_t enter_point = getFnpostion(symbol_addr,zygote_pid);
    printf("enter_point地址为: 0x%lx \n",enter_point);
    if(enter_point == 0){
        return 1;
    }
    //把hook的函数给读出来
    char remote_pattern[] = "/xzxzxrack87654321";
    uintptr_t pp = (uintptr_t) memmem(stub_binary, stub_binary_size, remote_pattern, sizeof remote_pattern);
    printf("pp:0x%lx",pp);
    //step4: 利用命令的方式将需注入的so文件写入目标app的catch目录，绕过selinux安全策略
    char targetDir[128];
    sprintf(targetDir,"/data/data/%s/cache/lib%d.so",package_name,yuid);
    char cpcmd[128];
    sprintf(cpcmd,"cp %s %s",so_path,targetDir);
    system(cpcmd);
    char chown_cmd[128];
    sprintf(chown_cmd,"chown %d:%d  %s",yuid,yuid,targetDir);
    system(chown_cmd);
    so_path = targetDir;
    uintptr_t shellcode_base = ts.end - getpagesize();
    uintptr_t original_ptr;
    char mempath[128];
    sprintf(mempath,"/proc/%d/mem",zygote_pid);
    int mem_fd = open(mempath, O_RDWR);
    pread(mem_fd,&original_ptr,sizeof(uintptr_t),enter_point);
    printf("[*] Verification: Slot 0x%lx contains 0x%lx shellcode base  0x%lx\n", enter_point, original_ptr,shellcode_base);

    uint8_t *original_shellcode_area = malloc(stub_binary_size);
    pread(mem_fd,(uint8_t*)original_shellcode_area,stub_binary_size,shellcode_base);

    uintptr_t offset = pp - (uintptr_t)stub_binary;

    TStub* tStub = (TStub*)(stub_binary + offset);

    tStub->uid = yuid;
    strcpy(tStub->so_path, so_path);

    //将shellcode中所使用到的函数进行重定位操作
    uintptr_t liblogbase = getsobase("liblog.so",zygote_pid);
    uintptr_t addr_log = liblogbase + getSymbolOffset("/system/lib64/liblog.so","__android_log_print");
    printf("addr_log 0x%lx \n",addr_log);

    uintptr_t libcbase = getsobase("libc.so",zygote_pid);
    uintptr_t addr_getuid = libcbase + getSymbolOffset("/system/lib64/libc.so","getuid");
    printf("getuid 0x%lx \n",addr_getuid);

    uintptr_t libdlbase = getsobase("libdl.so",zygote_pid);
    uintptr_t addr_dlopen = libdlbase + getSymbolOffset("/system/lib64/libdl.so","dlopen");
    printf("dlopen 0x%lx \n",addr_dlopen);


    tStub->log_print = (int (*)(int, const char*, const char*, ...))addr_log;
    tStub->getuid = (uid_t (*)())addr_getuid;
    tStub->dlopen = (void* (*)(const char*, int))addr_dlopen;

    tStub->original_set_argv0 = (int (*)(JNIEnv*,jobject,jstring))symbol_addr;
    tStub->slot_addr = enter_point;

    ssize_t written_code = pwrite(mem_fd,stub_binary,stub_binary_size,shellcode_base);
    if(written_code != stub_binary_size){
        printf("写入shellcode失败 \n");
    }
    uintptr_t new_ptr = shellcode_base;
    ssize_t written_ptr = pwrite(mem_fd, &new_ptr, sizeof(new_ptr), enter_point);
    if(written_ptr != sizeof(new_ptr)){
        printf("写入artmethod失败 \n");
    }
    printf("[!] HOOK SUCCESS! art_method_slot now points to Shellcode.\n");
    kill(zygote_pid, SIGCONT);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "am force-stop %s", package_name);
    system(cmd);

    char amscmd[512];
    sprintf(amscmd,"am start $(cmd package resolve-activity --brief '%s'| tail -n 1)",package_name);
    system(amscmd);

    printf("[*] Press Ctrl+C to restore and exit.\n");

    while (keep_running) {
        sleep(1);
    }

    printf("\n[*] Restoring Zygote memory...\n");
    kill(zygote_pid, SIGSTOP);

    pwrite(mem_fd, &original_ptr, sizeof(original_ptr), enter_point);
    pwrite(mem_fd, original_shellcode_area, stub_binary_size, shellcode_base);

    kill(zygote_pid, SIGCONT);

    close(mem_fd);
    printf("[+] Restore complete. Goodbye!\n");



}