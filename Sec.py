import os
from subprocess import Popen, PIPE, DEVNULL
import re
import sys
import argparse
import datetime
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('-c', action='store_true', help='show changed files (slow)')
parser.add_argument('-f', action='store_true', help='generate timeline')
parser.add_argument('-o', action='store_true', help='show open ports')
args = parser.parse_args()

def run_command(command, output_file):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    if result.returncode == 0:
        with open(output_file, 'w') as file:
            file.write(result.stdout)
    else:
        with open(output_file, 'w') as file:
            file.write(f"Error executing command: {command}\n")
            file.write(f"Error message: {result.stderr}\n")

def gather_system_info(output_dir):
    # Путь к файлам результата
    env_file = os.path.join(output_dir, "env_info.txt")
    user_file = os.path.join(output_dir, "user_info.txt")
    system_file = os.path.join(output_dir, "system_info.txt")
    history_file = os.path.join(output_dir, "history_info.txt")
    crontab_file = os.path.join(output_dir, "crontab_info.txt")
    process_file = os.path.join(output_dir, "process_info.txt")
    network_file = os.path.join(output_dir, "network_service.txt")

    # Выполняем команды и сохраняем результаты в файлы
    subprocess.run(["env"], stdout=open(env_file, "w"))
    subprocess.run(["id"], stdout=open(user_file, "w"))
    subprocess.run(["uname -a"], stdout=open(system_file, "w"), shell=True)
    subprocess.run(["history"], stdout=open(history_file, "w"), shell=True)
    subprocess.run(["crontab -l"], stdout=open(crontab_file, "w"), shell=True)
    subprocess.run(["ps aux"], stdout=open(process_file, "w"), shell=True)
    subprocess.run(["systemctl list-units --type=service --all"], stdout=open(network_file, "w"), shell=True)

    # Creating subdirectories for different categories
    os.makedirs(os.path.join(output_dir, 'mta', 'postfix'))
    os.makedirs(os.path.join(output_dir, 'mta', 'sendmail'))

    # Running additional commands and saving results to files
    run_command('systemctl --full --all', os.path.join(output_dir, 'systemctl.txt'))
    run_command('lshw', os.path.join(output_dir, 'lshw.txt'))
    run_command('cat /proc/cpuinfo', os.path.join(output_dir, 'cpuinfo.txt'))
    run_command('free -h', os.path.join(output_dir, 'memory.txt'))
    run_command('mount', os.path.join(output_dir, 'hdd.txt'))
    run_command('df -h', os.path.join(output_dir, 'hdd.txt'))
    run_command('df -hi', os.path.join(output_dir, 'hdd.txt'))
    run_command('cp /etc/passwd ' + os.path.join(output_dir, 'passwd'), os.devnull)
    run_command('cp /etc/group ' + os.path.join(output_dir, 'group'), os.devnull)
    # ... Add more commands as needed

# Создаем каталог для результатов
# Creating a directory for results
output_dir = f"Output_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
os.makedirs(output_dir)

# Gathering system information
try:
    gather_system_info(output_dir)
except FileNotFoundError as e:
    print(f"Error: {e}")
    sys.exit(1)


# Далее можно использовать содержимое output_dir по необходимости

def get_open_ports():
    process = Popen(["netstat", "-lntup"], stdout=PIPE, stderr=DEVNULL)
    output, _ = process.communicate()
    return output.decode("utf-8").split("\n")[2:]  # Skip header lines

def show_open_ports():
    open_ports = get_open_ports()
    print("\nOpen Ports:")
    print("{:<10} {:<20} {:<20} {:<20}".format("Proto", "Local Address", "Foreign Address", "PID/Program name"))
    for line in open_ports:
        print(line)


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
    outfile = args.f if args.f else sys.stdout
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
    elif args.o:
        print("Showing open ports")
        show_open_ports()
    else:
        print("Invalid arguments. Use -h for help.")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    if not any(vars(args).values()):
        print("No arguments provided. Use -h for help.")
        sys.exit(1)
    main()

