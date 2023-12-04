import os
from subprocess import Popen, PIPE, DEVNULL
import re
import sys
import argparse
import datetime
import subprocess

TMPE = "/path/to/tmp/directory"  # Замените на фактический путь к вашему временному каталогу


parser = argparse.ArgumentParser()
parser.add_argument('-c', action='store_true', help='show changed files (slow)')
parser.add_argument('-f', help='generate timeline and save to the specified file')
parser.add_argument('-d',  action='store_true', help="dump system info into current directory")
args = parser.parse_args()


def run_command(command, output_file):
    print(f"Executing command: {command}")
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    if result.returncode == 0:
        with open(output_file, 'w') as file:
            file.write(result.stdout)
    else:
        with open(output_file, 'w') as file:
            file.write(f"Error executing command: {command}\n")
            file.write(f"Error message: {result.stderr}\n")

def gather_system_info(output_dir):
    env_file = os.path.join(output_dir, "env_info.txt")
    user_file = os.path.join(output_dir, "user_info.txt")
    system_file = os.path.join(output_dir, "system_info.txt")
    history_file = os.path.join(output_dir, "history_info.txt")
    crontab_file = os.path.join(output_dir, "crontab_info.txt")
    process_file = os.path.join(output_dir, "process_info.txt")
    network_file = os.path.join(output_dir, "network_service.txt")

    run_command("env", env_file)
    run_command("id", user_file)
    run_command("uname -a", system_file)
    run_command("history", history_file)
    run_command("crontab -l", crontab_file)
    run_command("ps aux", os.path.join(output_dir, 'process_info.txt'))
    run_command("systemctl list-units --type=service --all", network_file)

    run_command('systemctl --full --all', os.path.join(output_dir, 'systemctl.txt'))
    run_command('lshw', os.path.join(output_dir, 'lshw.txt'))
    run_command('cat /proc/cpuinfo', os.path.join(output_dir, 'cpuinfo.txt'))
    run_command('free -h', os.path.join(output_dir, 'memory.txt'))
    run_command('mount', os.path.join(output_dir, 'hdd.txt'))
    run_command('df -h', os.path.join(output_dir, 'hdd.txt'))
    run_command('df -hi', os.path.join(output_dir, 'hdd.txt'))
    run_command('cp /etc/passwd ' + os.path.join(output_dir, 'passwd'), os.devnull)
    run_command('cp /etc/group ' + os.path.join(output_dir, 'group'), os.devnull)
    run_command("ss -lntup", os.path.join(output_dir, 'ss.txt'))
    run_command('netstat -lntup', os.path.join(output_dir, 'netstat.txt'))
    run_command('lsof -i', os.path.join(output_dir, 'lsof_another.txt'))

    run_command("ps axo state,pid,ppid,tid,pcpu,pmem,rsz,vsz,cmd", f"{output_dir}/ps.txt")
    run_command("ps axo state,pid,ppid,tid,pcpu,pmem,rsz,vsz,cmd -T", f"{output_dir}/pst.txt")
    run_command("pstree", f"{output_dir}/pstree.txt")
    run_command("top -b -n 1", f"{output_dir}/top.txt")
    run_command("top -bH -n 1", f"{output_dir}/toph.txt")
    # OS issue text (normally version)
    run_command("cat /etc/issue", f"{output_dir}/uname.txt")

    # OS issue and release text (normally version)
    run_command("ls /etc/issue /etc/*release", f"{output_dir}/os_release.txt")
    run_command("cat /etc/issue /etc/*release", f"{output_dir}/os_release.txt")

    # kernel parameters
    run_command("sysctl -a", f"{output_dir}/sysctl.txt")

    # SELinux status
    run_command("sestatus", f"{output_dir}/sestatus.txt")
    run_command("cp /etc/selinux/config", f"{output_dir}/seconfig.txt")

    # AppArmor status
    run_command("apparmor_status", f"{output_dir}/app_armor.txt")

    # loaded kernel modules
    run_command("lsmod", f"{output_dir}/lsmod.txt")

    # currently open files
    run_command("lsof -n", os.path.join(output_dir, 'lsof_files.txt'))

    # inter-process communication status (active message queues, semaphore sets, shared memory segments)
    run_command("ipcs -a", f"{output_dir}/ipcs.txt")

    # virtual memory statistics
    run_command("vmstat 1 10", f"{output_dir}/vmstat.txt")
    run_command("vmstat -d 1 10", f"{output_dir}/vmstatd.txt")
    run_command("vmstat -m 1 10", f"{output_dir}/vmstatm.txt")
    run_command("iostat -xk 1 10", f"{output_dir}/iostat.txt")

    # disk statistics
    run_command("vmstat -D", f"{output_dir}/vmstatd2.txt")

    # memory statistics
    run_command("vmstat -s", f"{output_dir}/vmstats.txt")

    # list installed rpm packages
    run_command("rpm -qa", f"{output_dir}/packages.txt")

    # list installed dpkg packages
    run_command("dpkg -l", f"{output_dir}/packages.txt")

    # python/python3 version
    run_command("echo 'python --version:'", f"{output_dir}/pythonvers.txt")
    run_command("python --version", f"{output_dir}/pythonvers.txt")
    run_command("echo 'python3 --version:'", f"{output_dir}/pythonvers.txt")
    run_command("python3 --version", f"{output_dir}/pythonvers.txt")

    # pip3 packages
    run_command("pip3 list", f"{output_dir}/pip3list.txt")

    # user limits
    run_command("ulimit -a", f"{output_dir}/ulimit.txt")

    # systemd dumps listing
    run_command("coredumpctl list", f"{output_dir}/coredumps.txt")
    run_command("ls -la /var/lib/systemd/coredump", f"{output_dir}/coredumps.txt")

    # routing information
    run_command("route -n", f"{output_dir}/route.txt")

    # network interfaces
    run_command("ifconfig", f"{output_dir}/ifconfig.txt")

    # network interfaces
    run_command("ip a", f"{output_dir}/ipa.txt")

    # network connections info
    run_command("netstat -apln", f"{output_dir}/netstat.txt")

    # list sockets
    run_command("ss -npatu", f"{output_dir}/ss.txt")

    # routing tables and rules
    run_command("ip -4 route ls", f"{output_dir}/ipv4routes.txt")
    run_command("ip -4 rule ls", f"{output_dir}/ipv4rules.txt")
    run_command("ip -6 route ls", f"{output_dir}/ipv6routes.txt")
    run_command("ip -6 rule ls", f"{output_dir}/ipv6rules.txt")

    # list iptables firewall rules
    run_command("iptables -L", f"{output_dir}/iptables.txt")
    run_command("iptables -nvL -t filter", f"{output_dir}/iptables-filter.txt")
    run_command("iptables -nvL -t mangle", f"{output_dir}/iptables-mangle.txt")
    run_command("iptables -nvL -t nat", f"{output_dir}/iptables-nat.txt")

    # list firewalld zones
    run_command("firewall-cmd --list-all-zones", f"{output_dir}/firewalld.zones.txt")

    # time system running, load average
    run_command("uptime", f"{output_dir}/uptime.txt")

    # get hostname
    run_command("hostname", f"{output_dir}/hostname.txt")

    # get hosts file
    run_command("cp /etc/hosts", f"{output_dir}/hosts.txt")

    # DNS resolver configuration
    run_command("cp /etc/resolv.conf", f"{output_dir}/resolv.conf")

    # get Cron scheduled scripts
    run_command(f"cp -vRL /etc/cron.daily/* {output_dir}", os.devnull)
    run_command('cp -RL /etc/cron.weekly/ ' + os.path.join(output_dir, 'cron_weekly'), os.devnull)
    run_command('cp -RL /etc/cron.monthly/ ' + os.path.join(output_dir, 'cron_monthly'), os.devnull)
    run_command(f"cp -vRL /etc/cron.hourly/ {output_dir}", f"{output_dir}/cron_hourly_log")
    run_command('cp -R /etc/rsyslog.d/ ' + os.path.join(output_dir, 'rsyslog.d'), os.devnull)
    run_command('cp /etc/rsyslog.conf ' + os.path.join(output_dir, 'rsyslog.conf'), os.devnull)

    # crontab scheduled scripts
    run_command('cp /etc/crontab ' + os.path.join(output_dir, 'crontab'), os.devnull)

    # get listing of system directories
    run_command("ls -la / /tmp /opt /var /etc /usr", f"{output_dir}/lsroot.txt")

    # get listing of system libs
    run_command("ls -la / /usr | grep lib", f"{output_dir}/lslib.txt")
    run_command("ls -laL /lib*", f"{output_dir}/lslib.txt")
    run_command("ls -laL /usr/lib*", f"{output_dir}/lslib.txt")

    # get current time
    run_command("date", f"{output_dir}/date.txt")
    run_command("LC_ALL=en_EN.utf8 date", f"{output_dir}/date_en.txt")

    # check if internet is available
    run_command("ping -c2 ya.ru", f"{output_dir}/ping.txt")

    # get sudo security policy configuration
    run_command("cp /etc/sudoers", f"{output_dir}/sudoers.txt")

    # get SSHD and systemd configuration options
    run_command("grep 'PasswordAuthentication\|ChallengeResponseAuthentication' /etc/ssh/sshd_config",
                f"{output_dir}/remote.txt")
    run_command("grep 'KillUserProcesses\|KillExcludeUsers' /etc/systemd/logind.conf", f"{output_dir}/remote.txt")

    # Samba config
    run_command("testparm -s", f"{output_dir}/smb.conf")


def show_changed_files():
    process = Popen(["dpkg", "--verify"], stdout=PIPE, stderr=PIPE)
    output, err = process.communicate()
    files = set(re.findall("/.*", output.decode('utf-8')))
    inaccessible = set(re.findall("unable to open (.*) for hash", err.decode("utf-8")))
    for fn in files - inaccessible:
        print(fn)



def get_package_files():
    process = Popen(["dpkg", "-S", "*"], stdout=PIPE, stderr=DEVNULL)
    output, err = process.communicate()
    return set(re.findall("/.*", output.decode('utf-8')))


def get_timeline():
    process = Popen(["find", "/", "-type", "d,f", "-xdev", "-printf", "%C@;%y%m;%u;%s;%p\n"], stdout=PIPE, stderr=DEVNULL)
    output, err = process.communicate()
    return output.decode("utf-8").split("\n")[:-1]  # last line is empty



def sizeof_fmt(num, suffix="B"):
    for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
        if abs(num) < 1024.0:
            return "{:3.1f}{}{}".format(num, unit, suffix)
        num /= 1024.0
    return "{:.1f}Yi{}".format(num, suffix)


def show_timeline():
    timeline = get_timeline()
    print("Files cnt: {}".format(len(timeline)))
    packageset = get_package_files()
    print("Files from repositories: {}".format(len(packageset)))
    filtered_timeline = []
    for fl in timeline:
        data = fl.split(";")
        ts = int(data[0].split('.')[0])
        perm = data[1]
        user = data[2]
        size = data[3]
        fname = ";".join(fl.split(";")[4:])
        if fname not in packageset:
            filtered_timeline.append((ts, user, perm, size, fname))
    print("Filtered timeline: {}".format(len(filtered_timeline)))
    output_file = args.f
    with open(output_file, 'w') as outfile:
        for line in sorted(filtered_timeline, reverse=True):
            ts, user, perm, size, fname = line
            size = sizeof_fmt(int(size))
            ctime = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            print("{:>8}\t{}\t{:>10}\t{:>20}\t{}".format(user, perm, size, ctime, fname), file=outfile)


def main():
    if args.c:
        print("Showing changed files")
        show_changed_files()
    elif args.f:
        print("Generating timeline")
        try:
            show_timeline()
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
    elif args.d:
        output_dir = f"Output_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        os.makedirs(output_dir)
        print(f"Dumping system info: {output_dir}")
        try:
            gather_system_info(output_dir)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        print("Invalid arguments. Use -h for help.")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    if not any(vars(args).values()):
        print("No arguments provided. Use -h for help.")
        sys.exit(1)
    main()

