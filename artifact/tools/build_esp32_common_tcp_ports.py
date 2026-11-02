#!/usr/bin/env python3
"""Build the same pinned original zperf TCP upload core on native FreeRTOS/NuttX."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from run_esp32_followup import sha

ROOT=Path(__file__).resolve().parents[1]
REPORTS=ROOT/"artifacts/reports"
ORIGINAL_SHA="a1584d7316755f75e7b8d0e1415d683d7e43802b91688752c2f6f946091d0ebe"
UDP_SHA="4e0dbe56c876a1c7d39c3e152efdfdeedb0d9de220a9aa3cd8b3c095393875e5"
COMMON_SHA="8c680aa02f85defdfe8e998b09aba70c500962a973419406bfaa9eb1af0cbfa1"
RECEIVER_SHA="6b1b0d0fc438d9b6496ee210e7cdf3a764363013c88c1fb822fdf4171dbb4e56"
SESSION_SHA="dd68ee576f1a6ce3f265aa588f9fc154c8d806e2a93616146554e6473e534fd6"
HOST_SOURCES={"Client.cpp":"9726720f459288b6b533178c016e4f9fa52b064b3056a84dd794ea4c30e35794",
              "Reporter.c":"9b708c6b0bcead9f3d91d105efd50b5b6a6b386cd38ef35c00876f40f6d83b27",
              "Settings.cpp":"4f0e3e97581a7a925f1bea277d37297ac970d409dbf2ce6e03004eda33ca5442"}


def archive_host_sources(root,out):
    target=out/"host-source"
    target.mkdir()
    for name,digest in HOST_SOURCES.items():
        source=root/"iperf-2.0.5/src"/name
        if sha(source)!=digest:
            raise ValueError("Original host sender/reporter source changed: "+name)
        shutil.copyfile(source,target/name)
    shutil.copyfile(root/"iperf-2.0.5/COPYING",target/"COPYING")


def original_receiver_parts():
    """Extract complete original functions and declarations without rewriting them."""
    folder=REPORTS/"esp32-network-common-zephyr-v2"
    paths={"receiver":folder/"zperf-library/zperf_udp_receiver.c",
           "session":folder/"zperf-library/zperf_session.c",
           "header":folder/"zperf-library/zperf_session.h",
           "internal":folder/"zperf-library/zperf_internal.h", "api":folder/"zperf.h"}
    expected={"receiver":RECEIVER_SHA,"session":SESSION_SHA,
              "header":"6bc609414926ae4aa0bdf8b11e6ff2061251ed4e8d4da11520cb5f9a660ca232",
              "internal":"fe650629aab8d36303f2b722eab1a8c93f7f51fe0594fe6494c65fa0bac831c9",
              "api":"e46d64ebae352c151e3d196551bd54e3fdc9aa16e7b6193c153d8bce27155d33"}
    for name,path in paths.items():
        if sha(path)!=expected[name]:
            raise ValueError("Pinned original UDP receiver source differs: "+name)
    texts={name:path.read_text() for name,path in paths.items()}
    license=lambda text:text[:text.index("*/")+2]+"\n"
    api=texts["api"]
    result=api[api.index("struct zperf_results {"):api.index("/**\n * @brief Synchronous UDP")]
    status=api[api.index("enum zperf_status {"):api.index("struct zperf_upload_params {")]
    internal=texts["internal"]
    declarations=internal[internal.index("struct zperf_udp_datagram {"):internal.index("struct zperf_async_upload_context {")]
    helper=internal[internal.index("static inline uint32_t time_delta("):internal.index("int zperf_get_ipv6_addr(")]
    header=texts["header"]
    session_types=header[header.index("enum state {"):header.index("struct session *get_session(")]
    receiver=texts["receiver"]
    session=texts["session"]
    return {"upstream_types.inc":license(api)+"#ifndef __ZEPHYR__\n"+status+result+"#endif\n"+
                license(internal)+declarations+helper+license(header)+session_types,
            "upstream_session.inc":license(session)+session[session.index("#define SESSION_MAX"):],
            "upstream_receiver.inc":license(receiver)+receiver[receiver.index("static inline void build_reply("):
                receiver.index("static void zperf_udp_join_mcast_ipv4(")]}


def original_core(protocol="tcp"):
    if protocol=="udp-receiver":
        return original_receiver_parts()["upstream_receiver.inc"]
    source=REPORTS/("esp32-network-common-zephyr-v2/zperf-library/zperf_"+protocol+"_uploader.c")
    if protocol not in ("tcp","udp") or sha(source)!=(ORIGINAL_SHA if protocol=="tcp" else UDP_SHA):
        raise ValueError("Pinned original TCP source differs")
    body=source.read_text()
    if protocol=="udp":
        common=source.with_name("zperf_common.c")
        if sha(common)!=COMMON_SHA:
            raise ValueError("Original packet-duration arithmetic differs")
        helper=common.read_text().split("uint32_t zperf_packet_duration(",1)[1].split("\nvoid zperf_async_work_submit",1)[0]
        return (body[:body.index("*/")+2]+"\nuint32_t zperf_packet_duration("+helper+"\n"+
            body[body.index("static uint8_t sample_packet["):body.index("static struct zperf_async_upload_context")]+
            body[body.index("static inline void zperf_upload_decode_stat("):body.index("static void udp_upload_async_work(")])
    begin=body.index("static ssize_t sendall(")
    end=body.index("static void tcp_upload_async_work(")
    # These three contiguous functions are copied byte-for-byte, not rewritten.
    return body[:body.index("*/")+2]+"\n"+body[begin:end]


def original_udp_types():
    parts=[]
    for filename,digest,names in (("zperf.h","e46d64ebae352c151e3d196551bd54e3fdc9aa16e7b6193c153d8bce27155d33",
            ("zperf_upload_params","zperf_results")),
            ("zperf-library/zperf_internal.h","fe650629aab8d36303f2b722eab1a8c93f7f51fe0594fe6494c65fa0bac831c9",
            ("zperf_udp_datagram","zperf_client_hdr_v1","zperf_server_hdr"))):
        path=REPORTS/"esp32-network-common-zephyr-v2"/filename
        if sha(path)!=digest:
            raise ValueError("Pinned original UDP ABI declarations differ")
        text=path.read_text()
        parts.append(text[:text.index("*/")+2])
        for name in names:
            begin=text.index("struct "+name+" {")
            end=text.index(";",text.index("} __packed" if name=="zperf_udp_datagram" else "};",begin))+1
            parts.append(text[begin:end])
    return "\n\n".join(parts)+"\n"


def command(args,cwd,env,output,name):
    with (output/name).open("x") as log:
        subprocess.run(list(map(str,args)),cwd=cwd,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)


def build(root,system,version="v1",protocol="tcp",resume_context=False):
    from audit_esp32_resources import audit_elf_image
    if protocol not in ("tcp","udp","udp-receiver"):
        raise ValueError("Unsupported original network protocol")
    short={"FreeRTOS":"freertos","NuttX":"nuttx"}[system]
    app_name={"tcp":"zperf_common","udp":"zperf_udp_common","udp-receiver":"zperf_udp_receiver"}[protocol]
    work=root/(("zperf-common-" if protocol=="tcp" else "zperf-"+protocol+"-common-")+short+"-work-"+version)
    out=REPORTS/("esp32-common-"+protocol+"-"+short+"-"+version)
    if resume_context:
        if system!="NuttX" or protocol!="udp-receiver" or not work.is_dir() or not out.is_dir() or \
                not (out/"context.log").is_file() or (out/"build.log").exists() or (out/"context-retry.log").exists():
            raise ValueError("Resume requires a preserved receiver dependency-context failure before compilation")
    elif work.exists() or out.exists():
        raise ValueError("Preserve existing build/failed attempt")
    else:
        out.mkdir(parents=True)
    gcc=root/"idf-tools/tools/xtensa-esp-elf/esp-13.2.0_20230928/xtensa-esp-elf/bin"
    env=dict(os.environ,PATH=str(gcc)+":"+str(root/"idf-python-env/bin")+":"+str(root/"python-nuttx/bin")+":"+str(root/"bin")+":"+os.environ["PATH"])
    adapter=ROOT/"firmware/bsp/esp32"/app_name
    if system=="FreeRTOS":
        project=work/"project"
        reference=REPORTS/"esp32-network-controlled-idf-v1"
        shutil.copytree(reference/"source",project,ignore=shutil.ignore_patterns("._*"))
        app=project/"main"
        shutil.copyfile(adapter/"port.c",app/(app_name+"_port.c"))
        main=app/"iperf_example_main.c"
        text=main.read_text()
        assert text.count("    register_wifi();")==1
        main.write_text(text.replace("    register_wifi();","    register_wifi();\n    extern void register_"+app_name+"(void);\n    register_"+app_name+"();"))
        cmakefile=app/"CMakeLists.txt"
        text=cmakefile.read_text()
        assert text.count('"iperf_example_main.c"')==1
        cmakefile.write_text(text.replace('"iperf_example_main.c"','"iperf_example_main.c" "'+app_name+'_port.c"'))
        write_core(app,protocol)
        shutil.copyfile(reference/"config",out/"config")
        env.update(IDF_PATH=str(root/"esp-idf-v5.2.5"),IDF_TOOLS_PATH=str(root/"idf-tools"),
                   IDF_PYTHON_ENV_PATH=str(root/"idf-python-env"),ESP_ROM_ELF_DIR=str(root/"idf-tools/tools/esp-rom-elfs/20230320"))
        cmake=root/"idf-tools/tools/cmake/3.30.2/bin/cmake"
        builddir=work/"build"
        command([cmake,"-G","Ninja","-S",project,"-B",builddir,"-DCOMPONENTS=main;esp_wifi;nvs_flash",
                 "-DIDF_TARGET=esp32","-DSDKCONFIG="+str(out/"config"),"-DPYTHON="+str(root/"idf-python-env/bin/python"),
                 "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],work,env,out,"configure.log")
        command([cmake,"--build",builddir,"--parallel","2"],work,env,out,"build.log")
        for name,saved in (("iperf.elf","application.elf"),("iperf.bin","application.bin"),
                           ("bootloader/bootloader.bin","bootloader.bin"),("partition_table/partition-table.bin","partitions.bin"),
                           ("compile_commands.json","compile_commands.json")):
            shutil.copyfile(builddir/name,out/saved)
    else:
        base=root/"nuttx-iperf-original-work"
        reference=REPORTS/"esp32-network-controlled-nuttx-v2"
        app=work/"apps/examples"/app_name
        source=work/"nuttx"
        if not resume_context:
            shutil.copytree(base,work,symlinks=True,ignore=shutil.ignore_patterns("*.o",".git"))
            for directory,dirs,files in os.walk(work,followlinks=False):
                for name in dirs+files:
                    path=Path(directory)/name
                    if path.is_symlink() and os.readlink(path).startswith(str(base)+"/"):
                        target=str(work)+os.readlink(path)[len(str(base)):]
                        path.unlink()
                        path.symlink_to(target)
            shutil.copytree(adapter,app)
            write_core(app,protocol)
            command(["make","distclean"],source,env,out,"distclean.log")
            shutil.copyfile(reference/"config",source/".config")
            shutil.copyfile(source/"boards/xtensa/esp32/esp32-devkitc/scripts/Make.defs",source/"Make.defs")
            command(["make","apps_preconfig"],source,env,out,"configure.log")
            selected=dict(env,APPSDIR="../apps",APPSBINDIR="../apps",BINDIR=str(source),EXTERNALDIR="dummy")
            command(["setconfig","EXAMPLES_"+app_name.upper()+"=y"],source,selected,out,"select.log")
            command(["make","olddefconfig"],source,env,out,"olddefconfig.log")
            command(["tools/version.sh","-v","12.2.1","-b","snapshot-nuttx-12.2.1",".version"],source,env,out,"version.log")
        elif any((app/p.name).read_bytes()!=p.read_bytes() for p in adapter.iterdir() if p.is_file()) or \
                any((app/n).read_text()!=text for n,text in original_receiver_parts().items()):
            raise ValueError("Preserved receiver source changed before context resume")
        if protocol=="udp-receiver":
            for relative,saved,digest in (("system/argtable3/v3.2.0.7402e6e.tar.gz","argtable3",
                    "e692ce51fb51dc750b47ef0ef2941573c8c49195aa2ddc48cb369239c400efa7"),
                    ("netutils/cjson/v1.7.12.tar.gz","cjson","760687665ab41a5cff9c40b1053c19572bcdaadef1194e5cba1b5e6f824686e7")):
                cached=base/"apps"/relative
                if sha(cached)!=digest: raise ValueError("Pinned original dependency differs: "+saved)
                shutil.copyfile(cached,work/"apps"/relative)
                archived=out/("dependency-"+saved+".tar.gz")
                if archived.exists():
                    if sha(archived)!=digest: raise ValueError("Previously archived dependency changed")
                else: shutil.copyfile(cached,archived)
        command(["make","context"],source,env,out,"context-retry.log" if resume_context else "context.log")
        command(["make","clean"],source,env,out,"clean.log")
        command(["make","--jobs=2","V=1"],source,env,out,"build.log")
        for name,saved in (("nuttx","application.elf"),("nuttx.bin","application.bin"),(".config","config")):
            shutil.copyfile(source/name,out/saved)
        for name,saved in (("bootloader-esp32.bin","bootloader.bin"),("partition-table-esp32.bin","partitions.bin")):
            shutil.copyfile(work/name,out/saved)
    command([gcc/"xtensa-esp32-elf-gcc","--version"],work,env,out,"compiler.txt")
    shutil.copyfile(reference/"config",out/"reference-config")
    shutil.copytree(app,out/"application-source")
    original_name="zperf_udp_receiver.c" if protocol=="udp-receiver" else "zperf_"+protocol+"_uploader.c"
    shutil.copyfile(REPORTS/"esp32-network-common-zephyr-v2/zperf-library"/original_name,out/"upstream-full.c")
    if protocol in ("udp","udp-receiver"):
        for original,saved in (("zperf-library/zperf_common.c","upstream-common.c"),
                               ("zperf-library/zperf_internal.h","upstream-internal.h"),("zperf.h","upstream-api.h")):
            shutil.copyfile(REPORTS/"esp32-network-common-zephyr-v2"/original,out/saved)
    if protocol=="udp-receiver":
        for name in ("zperf_session.c","zperf_session.h"):
            shutil.copyfile(REPORTS/"esp32-network-common-zephyr-v2/zperf-library"/name,out/name)
        archive_host_sources(root,out)
    shutil.copyfile(root/"zephyr-v3.7.0-work/zephyr/LICENSE",out/"LICENSE")
    shutil.copyfile(Path(__file__),out/"build-script.py")
    finish(out,system,protocol)


def write_core(app,protocol):
    if protocol=="udp-receiver":
        for name,text in original_receiver_parts().items(): (app/name).write_text(text)
    else:
        (app/("upstream_"+protocol+".inc")).write_text(original_core(protocol))
        if protocol=="udp": (app/"upstream_types.inc").write_text(original_udp_types())


def finish(out,system,protocol):
    """Finish source/image audit after successful compilation, without rebuilding."""
    from audit_esp32_resources import audit_elf_image
    if (out/"build.json").exists():
        raise ValueError("Preserve an existing sealed build")
    app=out/"application-source"
    core_name="upstream_receiver.inc" if protocol=="udp-receiver" else "upstream_"+protocol+".inc"
    digest={"tcp":ORIGINAL_SHA,"udp":UDP_SHA,"udp-receiver":RECEIVER_SHA}[protocol]
    if (app/core_name).read_text()!=original_core(protocol) or sha(out/"upstream-full.c")!=digest:
        raise ValueError("Existing compiled source does not match pinned original")
    shutil.copyfile(Path(__file__),out/"finalize-script.py")
    audit_elf_image(out/"application.elf",out/"application.bin")
    manifest={"built":True,"measured":False,"system":system,"protocol":protocol,
              "original_full_source_sha256":digest,
              "included_core_sha256":sha(app/core_name),"packet_bytes":16384 if protocol=="tcp" else 1024,"seconds":60,
              "tick_hz":100,"clock_mhz":240,"cores":1,"native_interface":
              "BSD send/connect/close, native tick counter and yield" if protocol=="tcp" else
              "BSD datagram socket/timeout, native 100-Hz ticks and relative timed sleep; original pacing function" if protocol=="udp" else
              "BSD datagram receive/poll/sendto; native 100-Hz clock; original receiver/session/statistic functions",
              "files":{p.relative_to(out).as_posix():sha(p) for p in out.rglob("*") if p.is_file()}}
    (out/"build.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps({k:v for k,v in manifest.items() if k!="files"},indent=2))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,default=Path.home()/"esp32-pilot")
    p.add_argument("--system",choices=("FreeRTOS","NuttX"),required=True)
    p.add_argument("--version",choices=("v1","v2"),default="v1")
    p.add_argument("--protocol",choices=("tcp","udp","udp-receiver"),default="tcp")
    p.add_argument("--finalize",action="store_true",help="Audit already built images without repeating compilation")
    args=p.parse_args()
    if args.finalize:
        finish(REPORTS/("esp32-common-"+args.protocol+"-"+args.system.lower()+"-"+args.version),args.system,args.protocol)
    else:
        build(args.root,args.system,args.version,args.protocol)
