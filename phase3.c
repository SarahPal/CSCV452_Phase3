#include <stdio.h>

#include <usloss.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>
#include <usyscall.h>
#include <libuser.h>
#include <provided_prototypes.h>

#include "sems.h"

#define debugflag3 0

semaphore 	running;


/* PROTOTYPES */
extern int start3(char *);

int start2(char *);
int  spawn_real(char *name, int (*func)(char *), char *arg,
                int stack_size, int priority);
int  wait_real(int *status);
int spawn();
void terminate(sysargs *args);
void terminate_real(int status);

static void check_kernel_mode(char *caller_name);

semaphore SemTable[MAXSEMS];
proc_struct ProcTable[MAXPROC];

int start2(char *arg)
{
    int		pid;
    int		status;
    /*
     * Check kernel mode here.
     */
     check_kernel_mode("start2");

    /*
     * Data structure initialization as needed...
     */


    /*
     * Create first user-level process and wait for it to finish.
     * These are lower-case because they are not system calls;
     * system calls cannot be invoked from kernel mode.
     * Assumes kernel-mode versions of the system calls
     * with lower-case names.  I.e., Spawn is the user-mode function
     * called by the test cases; spawn is the kernel-mode function that
     * is called by the syscall_handler; spawn_real is the function that
     * contains the implementation and is called by spawn.
     *
     * Spawn() is in libuser.c.  It invokes usyscall()
     * The system call handler calls a function named spawn() -- note lower
     * case -- that extracts the arguments from the sysargs pointer, and
     * checks them for possible errors.  This function then calls spawn_real().
     *
     * Here, we only call spawn_real(), since we are already in kernel mode.
     *
     * spawn_real() will create the process by using a call to fork1 to
     * create a process executing the code in spawn_launch().  spawn_real()
     * and spawn_launch() then coordinate the completion of the phase 3
     * process table entries needed for the new process.  spawn_real() will
     * return to the original caller of Spawn, while spawn_launch() will
     * begin executing the function passed to Spawn. spawn_launch() will
     * need to switch to user-mode before allowing user code to execute.
     * spawn_real() will return to spawn(), which will put the return
     * values back into the sysargs pointer, switch to user-mode, and
     * return to the user code that called Spawn.
     */
    pid = spawn_real("start3", start3, NULL, 4*USLOSS_MIN_STACK, 3);
    pid = wait_real(&status);

} /* start2 */


int spawn()
{
   //Not sure what goes in here..
  //at some point, call spawn_real
}
int  spawn_real(char *name, int (*func)(char *), char *arg, int stack_size, int priority)
{

  /*int pid = fork1(name, spawnLaunch, arg, stack_size, priority);

  if(pid < 0)
  {
    return -1;
  }

  //Do some process stuff in here...
  return pid; */
}

void terminate(sysargs *args)
{

  int status = (int)((long) args->arg1);
  terminate_real(status);
}

void terminate_real(int status)
{
  //zap childrem
  //remove process from list of children
  //quit
}

/*----------------------------------------------------------------*
 * Name        : check_kernel_mode                                *
 * Purpose     : Checks the current kernel mode.                  *
 * Parameters  : name of calling function                         *
 * Returns     : nothing                                          *
 * Side Effects: halts process if in user mode                    *
 *----------------------------------------------------------------*/
static void check_kernel_mode(char *caller_name)
{
    union psr_values caller_psr;                                        /* holds the current psr values */
    if (DEBUG3 && debugflag3)
       console("    - check_kernel_mode(): called for function %s -\n", caller_name);

 /* checks if in kernel mode, halts otherwise */
    caller_psr.integer_part = psr_get();                               /* stores current psr values into structure */
    if (caller_psr.bits.cur_mode != 1)
    {
       console("        - %s(): called while not in kernel mode, by process. Halting... -\n", caller_name);
       halt(1);
    }
}/* check_kernel_mode */
