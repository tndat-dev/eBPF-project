import json
from types import SimpleNamespace
import pytest
from sentinel_pulse.attack_trial import select_target


def pod(name, uid, container):
    return dict(metadata=dict(name=name,uid=uid), spec=dict(nodeName='node',containers=[dict(name=container)]),
                status=dict(phase='Running',conditions=[dict(type='Ready',status='True')],containerStatuses=[dict(ready=True)]))


class Runtime:
    def __init__(self, wrong=False):self.reads=0;self.wrong=wrong
    def kubectl_json(self,*_):
        return dict(items=[pod('aims-redis-sentinel-server-0','foreign','aims-redis'),pod('aims-redis-0','exact','aims-redis')])
    def remote_sudo(self,*_):
        self.reads+=1
        return SimpleNamespace(stdout=json.dumps(dict(cgroups={
            '1':dict(pod_uid='foreign',container_name='aims-redis',namespace='production',workload_name='aims-redis-sentinel-server'),
            '2':dict(pod_uid='exact',container_name='aims-redis',namespace='production',workload_name='foreign' if self.wrong else 'aims-redis')})).encode())


def test_overlapping_redis_prefix_does_not_select_sentinel_controller():
    runtime=Runtime()
    row=dict(workload_controller='aims-redis',workload_key='production/aims-redis:aims-redis')
    selected=select_target(runtime,row,{'node':dict(host='worker')},1)
    assert selected[0]['uid']=='exact'
    assert selected[3]==2
    assert runtime.reads==1


def test_missing_or_foreign_identity_cannot_be_relabelled_as_target():
    row=dict(workload_controller='aims-redis',workload_key='production/aims-redis:aims-redis')
    with pytest.raises(RuntimeError,match='exact ready'):
        select_target(Runtime(True),row,{'node':dict(host='worker')},1)
