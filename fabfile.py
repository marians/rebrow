#!/usr/bin/env python
"""
Fabfile to deploy rebrow
"""

import os
import StringIO

import boto3

from fabric.api import (cd, env, execute, hide, lcd, local, put, run,
                        runs_once, settings, task)

env.application = 'rebrow'
env.forward_agent = True
env.timeout = 15
env.user = "des"
env.connection_attempts = 5
env.use_ssh_config = True
env.remote_dir = '/data/apps/{}'.format(env.application)
env.home = '/home/des'
env.virtualenv = env.application
env.remote_release_dir = "%s/releases" % env.remote_dir
env.local_dir = os.path.dirname(os.path.realpath(__file__))
env.supervisorctl_path = "/bin/supervisorctl"


def aws_get_instance_dns_names(environment='dev'):
    """Get the instance dns names"""
    names = []
    aws_client = boto3.client('ec2', region_name='us-east-1')
    f = [
        {
            'Name': 'tag:client',
            'Values': [env.application]
        },
        {
            'Name': 'tag:organization',
            'Values': ['des']
        },
        {
            'Name': 'tag:role',
            'Values': ['web']
        },
        {
            'Name': 'tag:env',
            'Values': [environment]
        },
        {
            'Name': 'network-interface.status',
            'Values': ['in-use']
        }
    ]
    response = aws_client.describe_instances(Filters=f)
    for r in response['Reservations']:
        for i in r['Instances']:
            names.append(i['PrivateDnsName'])
    return names


@task
def deploy(symlink='current', branch='', client='', environment='', variant='',
           hostfilter='', deploy_command=''):
    """Main deploy task"""
    if hostfilter:
        env.hosts = get_hosts(hostfilter)
    else:
        env.hosts = aws_get_instance_dns_names(environment=environment)

    execute(archive)
    execute(create_release_folder)
    execute(transfer_archive)
    execute(unzip_archive)
    execute(create_sym_link, name=symlink)
    execute(pip_install, symlink=symlink)
    execute(delete_archive)
    execute(update_supervisorctl)


def get_hosts(h):
    """Parse host filters"""
    if h:
        x = [y.strip() for y in h.split(";")]
        if x:
            return x
    return False


@runs_once
def archive():
    with lcd(env.local_dir):
        env.commit = local('git log --pretty=format:\'%h\' -n 1', capture=True)
        base = local('basename $(git rev-parse --show-toplevel)', capture=True)
        env.archive_file = "%s-%s.zip" % (base, env.commit,)
        local('git archive HEAD --format=zip > %s' % env.archive_file)


def create_release_folder():
    run('mkdir -p {}'.format(env.remote_release_dir))
    with cd(env.remote_release_dir):
        run('rm -rf %s' % env.commit)
        run('mkdir %s' % env.commit)


def transfer_archive():
    local('scp {} {}@{}:{}/{}'.format(env.archive_file, env.user, env.host,
                                      env.remote_release_dir, env.commit))


def unzip_archive():
    with cd(env.remote_dir):
        with cd("%s/%s" % (env.remote_release_dir, env.commit,)):
            with hide('output'):
                run('unzip %s' % env.archive_file)


def create_sym_link(name):
    with cd(env.remote_dir):
        run('rm -rf %s' % name)
        run('ln -s %s/%s %s' % (env.remote_release_dir, env.commit, name,))


def delete_archive():
    with cd(env.remote_release_dir):
        run('rm -rf {}/{}'.format(env.commit, env.archive_file))
    with lcd(env.local_dir):
        local('rm -rf {}'.format(env.archive_file))


@task
def update_supervisorctl():
    """Update supervisord, restart process for new changes to take effect"""
    run("sudo %s reread" % (env.supervisorctl_path,))
    run("sudo %s update" % (env.supervisorctl_path,))
    run("sudo %s restart all" % (env.supervisorctl_path,))


@task
def pip_install(symlink='current'):
    """Install packages"""
    virtualenv = '{}/.virtualenvs/{}/'.format(env.home, env.virtualenv)
    with settings(warn_only=True):
        dir_exists = run('[ -d {} ] && echo 1'.format(virtualenv))
    if dir_exists != '1':
        run('export SLUGIFY_USES_TEXT_UNIDECODE=yes')
        run('mkvirtualenv {}'.format(env.virtualenv))
    prod_file = '{}/{}/requirements.txt'
    requirements = prod_file.format(env.remote_dir, symlink)
    install = '{}/.virtualenvs/{}/bin/pip install -r {}'
    with hide('output'):
        run(install.format(env.home, env.virtualenv, requirements))


@task
def git_version(symlink='current'):
    """Git version."""
    git_version = '{}/{}/git_version'.format(env.remote_dir, symlink)
    put(StringIO.StringIO(env.commit), git_version)
