#!/usr/bin/python

import os
import stat
import shutil
import argparse
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--testdir', dest = 'test_dir',
                    required = False, default = 'linux_apps')
parser.add_argument('--jobs', dest = 'jobs', required = False, default = 1)
args = parser.parse_args()

root = os.environ['PWD']
root = os.path.join(root, 'build_linux')
linux_dir = os.path.join(root, 'riscv-linux')
config_dir = os.path.join(root, 'linux_configs')
build_dir = os.path.join(root, '../build')
sm_kernel = os.path.join(root, 'sm_kernel_module')
test_dir = '' if args.test_dir == '' else os.path.abspath(args.test_dir)

# copy initramfs.txt and .config
shutil.copy(os.path.join(config_dir, 'linux_config'),
            os.path.join(linux_dir, '.config'))
shutil.copy(os.path.join(config_dir, 'initramfs.txt'), linux_dir)

# append to initramfs.txt with contents in test folder
if test_dir != '':
    with open(os.path.join(linux_dir, 'initramfs.txt'), 'a') as fp:
        def writeTree(ramfs_dir, src_dir):
            for f in os.listdir(src_dir):
                ramfs_path = os.path.join(ramfs_dir, f)
                src_path = os.path.join(src_dir, f)
                mode = os.stat(src_path).st_mode
                perm = oct(stat.S_IMODE(mode))[-3:]
                if stat.S_ISDIR(mode):
                    fp.write('dir {} {} 0 0\n'.format(ramfs_path, perm))
                    writeTree(ramfs_path, src_path)
                elif stat.S_ISREG(mode):
                    fp.write('file {} {} {} 0 0\n'.format(ramfs_path,
                                                        src_path,
                                                        perm))
                else:
                    raise Exception('unknown file type ' + src_path)
        #writeTree('/test', test_dir)
        writeTree('/test', sm_kernel)

# compile vmlinux
cmd = 'cd {}; make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- -j{}'.format(linux_dir, args.jobs)
print('Running: {}'.format(cmd))
subprocess.check_call(cmd, shell = True)

