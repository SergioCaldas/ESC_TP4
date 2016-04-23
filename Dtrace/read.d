#!/usr/sbin/dtrace -s

#pragma D option quiet

syscall::open*:entry
/execname=="iozone" & uid==29231/
{
	self->path = copyinstr(arg1);
	self->flag = arg2;
}

syscall::open*:return
/self->path=="iozone.tmp" /
{
	self->start_time = timestamp;
	total_time=0;
	size = 0;
	flag = 1;
	total_time_io = 0;
}

syscall::read:return
/self->start_time> 0/
{
	self->r_size = (arg0/1024);	
	size = size + self->r_size;
}

syscall::close*:entry
/self->path=="iozone.tmp" /
{
	self->stop_time = timestamp;
	self->elapsed = self->stop_time - self->start_time;
	total_time = total_time + self->elapsed; 
	printf("%-12s %s\n","SIZE","ELAPSED TIME");
	printf("%-12d %d\n",size,total_time);
	flag = 0;
}
