#include <usloss.h>

int waiting =0;

void
p1_fork(int pid)
{}

void
p1_switch(int old, int new)
{}

void
p1_quit(int pid)
{}

//REDEFINE REVIEW FEB 22 MEETING
int check_io()
{
    //Return 1 if at least one process is blocked on an I/O MailBox
    //Return 0 otherwise
    if(waiting > 0)
    {
        return 1;
    }
    return 0;
}
void add_process()
{
    waiting++;
}
void release_process()
{
    waiting--;
}
