#!/usr/sbin/dtrace -s

#pragma D option quiet

BEGIN
{
  baseline = walltimestamp;
  scale = 1000000;
}
sched:::on-cpu
/pid == $target && !self->stamp /
{
  self->stamp = walltimestamp; 
  self->lastcpu = curcpu->cpu_id;
  self->lastlgrp = curcpu->cpu_lgrp;
  self->stamp = (walltimestamp - baseline) / scale;
  printf("%9d:%-9d TID %3d CPU %3d(%d) created\n",
      self->stamp, 0, tid, curcpu->cpu_id, curcpu->cpu_lgrp);
  /*ustack(); */
}
sched:::on-cpu
/pid == $target && self->stamp && self->lastcpu\
      != curcpu->cpu_id/
{
  self->delta = (walltimestamp - self->stamp) / scale;
  self->stamp = walltimestamp;
  self->stamp = (walltimestamp - baseline) / scale;
  printf("%9d:%-9d TID %3d  from-CPU %d(%d) ",self->stamp,
      self->delta, tid, self->lastcpu, self->lastlgrp);
  printf("to-cpu %d(%d) CPU migration\n",
      curcpu->cpu_id, curcpu->cpu_lgrp);
  self->lastcpu =curcpu->cpu_id;
  self->latgrp = curcpu->cpu_lgrp;
}
sched:::on-cpu
/pid == $target && self->stamp && self->lastcpu\
      == curcpu->cpu_id/
{
  self->delta = (walltimestamp - self->stamp) / scale;
  self->stamp = walltimestamp; 
  self->stamp = (walltimestamp - baseline) / scale;
  printf("%9d:%-9d TID %3d CPU %3d(%d) ",self->stamp,
      self->delta, tid, curcpu->cpu_id, curcpu->cpu_lgrp);
  printf("restarted on the same CPU\n");
}
sched:::off-cpu
/pid == $target && self->stamp /
{
  self->delta = (walltimestamp - self->stamp) / scale;
  self->stamp = walltimestamp; 
  self->stamp = (walltimestamp - baseline) / scale;
  printf("%9d:%-9d TID %3d CPU %3d(%d) preempted\n",
      self->stamp, self->delta, tid, curcpu->cpu_id,
      curcpu->cpu_lgrp);
}
sched:::sleep
/pid == $target /
{
  self->sobj = (curlwpsinfo->pr_stype == SOBJ_MUTEX ?
      "kernel mutex" : curlwpsinfo->pr_stype == SOBJ_RWLOCK ?
      "kernel RW lock" : curlwpsinfo->pr_stype == SOBJ_CV ?
      "cond var" : curlwpsinfo->pr_stype == SOBJ_SEMA ?
      "kernel semaphore" : curlwpsinfo->pr_stype == SOBJ_USER ?
      "user-level lock" : curlwpsinfo->pr_stype == SOBJ_USER_PI ?
      "user-level PI lock" : curlwpsinfo->pr_stype == SOBJ_SHUTTLE ?
      "shuttle" : "unknown");
  self->delta = (walltimestamp - self->stamp) /scale;
  self->stamp = walltimestamp; 
  self->stamp = (walltimestamp - baseline) / scale;
  printf("%9d:%-9d TID %3d sleeping on '%s'\n",
      self->stamp, self->delta, tid, self->sobj);
  /* @sleep[curlwpsinfo->pr_stype, curlwpsinfo->pr_state, ustack()]=count(); */
}
sched:::sleep
/ pid == $target && ( curlwpsinfo->pr_stype == SOBJ_CV ||
    curlwpsinfo->pr_stype == SOBJ_USER ||
    curlwpsinfo->pr_stype == SOBJ_USER_PI) /
{
  /*ustack()*/
}
sched:::sleep
/pid!=$pid && 0/
{
  @sleep[execname,curlwpsinfo->pr_stype, curlwpsinfo->pr_state, ustack()]=count(); 
}
