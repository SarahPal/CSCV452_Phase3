#include <stdio.h>
#include <string.h>

#include <usloss.h>
#include <phase1.h>
#include <phase2.h>
#include <phase3.h>
#include <usyscall.h>
#include <libuser.h>
#include <provided_prototypes.h>

#include "sems.h"

#define debugflag3 1

semaphore 	running;


/* PROTOTYPES */
extern int start3(char *);

int start2(char *);
int  spawn_real(char *name, int (*func)(char *), char *arg,
                int stack_size, int priority);
int  wait_real(int *status);
void spawn(sysargs *args);
void terminate(sysargs *args);
void terminate_real(int status);
void add_child(int parentID, int childID);
int spawn_launch(char *arg);
void remove_child(int parentID, int childID);
void clear_proc(int status);


static void check_kernel_mode(char *caller_name);
void setUserMode();

semaphore SemTable[MAXSEMS];
proc_struct ProcTable[MAXPROC];


int numProcs = 3;

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
     for(int i = 0; i < MAXPROC; i++)
     {
         ProcTable[i].childProcPtr = NULL;
         ProcTable[i].nextSiblingPtr = NULL;
         ProcTable[i].name[0] = '\0';
         //ProcTable[i].startArg[0] = '\0';
         ProcTable[i].pid = UNUSED;
         ProcTable[i].ppid = UNUSED;
         ProcTable[i].priority = UNUSED;
         ProcTable[i].start_func = NULL;
         ProcTable[i].stack_size = UNUSED;
         ProcTable[i].spawnBox = MboxCreate(1, MAXLINE);
         memset(ProcTable[i].startArg, 0, sizeof(char)*MAXARG);
     }

     if(DEBUG3 && debugflag3)
     {
         console("    - start2(): process table initialized\n");
     }
     for(int i = 0; i < MAXSEMS; i++)
     {
         SemTable[i].mutexBox = UNUSED;
         SemTable[i].blockedBox = UNUSED;
         SemTable[i].value = 0;
         SemTable[i].blocked = 0;
     }
     if(DEBUG3 && debugflag3)
     {
         console("    - start2(): semaphore table initialized\n");
     }
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
    if(pid > 0)
    {
        pid = wait_real(&status);
    }
    return pid;

} /* start2 */

int  wait_real(int *status)
{
    if(DEBUG3 && debugflag3)
    {
        console("    - wait_real(): wait_real reached\n");
    }
    int result = join(status);

    if(is_zapped())
    {
        terminate_real(0);
    }

    return result;
} /* wait_real */

void spawn(sysargs *args)
{
    if(DEBUG3 && debugflag3)
    {
        console("    - spawn(): spawn reached\n");
    }
   char *name = args->arg5;
   int (*func)(char *) = args->arg1;
   char *arg = args->arg2;
   int stack_size = (long)args->arg3;
   int priority = (long) args->arg4;

   if(func == NULL || stack_size < USLOSS_MIN_STACK || numProcs > MAXPROC)
   {
       if(DEBUG3 && debugflag3)
       {
           console("    - spawn(): invalid arguments. Returning...\n");
       }
       args->arg4 = (void *)UNUSED;
       return;
   }

   int pid = spawn_real(name, func, arg, stack_size, priority);

   args->arg1 = (void *) pid;
   args->arg4 = (void *) 0;

   setUserMode();
   return;
} /* spawn */

int  spawn_real(char *name, int (*func)(char *), char *arg, int stack_size, int priority)
{
    if(DEBUG3 && debugflag3)
        console("    - spawn_real(): spawn_real reached\n");

  int pid = fork1(name, spawn_launch, arg, stack_size, priority);

  if(pid == -1)
  {
      if(DEBUG3 && debugflag3)
        console("    - spawn_real(): pid is -1. returning...\n");
      return pid;
  }

  int slot = pid % MAXPROC;
  ProcTable[slot].pid = pid;
  memcpy(ProcTable[slot].name, name, strlen(name));

  if(arg != NULL)
  {
      memcpy(ProcTable[slot].startArg, arg, strlen(arg));
  }
  ProcTable[slot].priority = priority;
  ProcTable[slot].start_func = func;
  ProcTable[slot].stack_size = stack_size;
  ProcTable[slot].ppid = getpid();

  add_child(getpid(), pid);

  if(ProcTable[pid%MAXPROC].priority < ProcTable[getpid()%MAXPROC].priority)
  {
      MboxSend(ProcTable[slot].spawnBox, NULL, 0);
      console("Message Sent\n");
  }

  if(is_zapped())
  {
      if(DEBUG3 && debugflag3)
      {
          console("    - spawn(): process is zapped. Terminating.\n");
      }
      terminate_real(0);
  }
  return pid;
} /* spawn_real */

int spawn_launch(char *arg)
{
    if(DEBUG3 && debugflag3)
    {
        console("    - spawn_launch(): spawn_launch reached\n");
    }

    int pid = (getpid()) % MAXPROC;
    int result;

    proc_ptr process = &ProcTable[pid];

    if(process->pid == -1)
    {
        //initialize process...
        /*ProcTable[pid].pid = pid;
        ProcTable[pid].spawnBox = MboxCreate(0,0);
        ProcTable[pid].start_func = NULL;
        ProcTable[pid].childProcPtr = NULL; */
        MboxReceive(ProcTable[pid].spawnBox, NULL, 0);
    }

    if(is_zapped())
    {;
        terminate_real(0);
        return 0;
    }
    setUserMode();

    result = process->start_func(arg);
    console("result set");
    Terminate(result);
    return result;
} /* spawn_launch */


void terminate(sysargs *args)
{
  if(DEBUG3 && debugflag3)
  {
      console("    - terminate(): terminate reached\n");
  }
  int status = (int)((long) args->arg1);
  terminate_real(status);
  setUserMode();
} /* terminate */

void terminate_real(int status)
{
    if(DEBUG3 && debugflag3)
    {
        console("    - terminate_real(): terminate_real reached\n");
    }
    proc_struct process = ProcTable[getpid()%MAXPROC];

    if(process.num_children != 0)
    {
        int children[MAXPROC];
        int i = 0;
        for(proc_ptr child = process.childProcPtr; child != NULL; child =
            child->nextSiblingPtr)
        {
            children[i] = child->pid;
            i++;
        }
        for(i = 0; i < process.num_children; i++)
        {
            zap(children[i]);
        }
    }
    remove_child(process.ppid, process.pid);
    clear_proc(getpid()%MAXPROC);

    quit(status);

    numProcs--;
} /*terminate_real */

void clear_proc(int slot)
{
    ProcTable[slot].childProcPtr = NULL;
    ProcTable[slot].nextSiblingPtr = NULL;
    ProcTable[slot].name[0] = '\0';
    ProcTable[slot].startArg[0] = '\0';
    ProcTable[slot].pid = UNUSED;
    ProcTable[slot].ppid = UNUSED;
    ProcTable[slot].priority = UNUSED;
    ProcTable[slot].start_func = NULL;
    ProcTable[slot].stack_size = UNUSED;
    ProcTable[slot].spawnBox = MboxCreate(0, MAX_MESSAGE);
} /*clear_proc */

void add_child(int parentID, int childID)
{
    if(DEBUG3 && debugflag3)
    {
        console("    - add_child(): adding child to process table\n");
    }
    parentID %= MAXPROC;
    childID %= MAXPROC;

    ProcTable[parentID].num_children++;

    if(ProcTable[parentID].childProcPtr == NULL)
    {
        ProcTable[parentID].childProcPtr = &ProcTable[childID];
    }
    else{
        proc_ptr child;

        for(child = ProcTable[parentID].childProcPtr; child->nextSiblingPtr != NULL;
            child = child->nextSiblingPtr)
        {
            child->nextSiblingPtr = &ProcTable[childID];
        }
    }
    numProcs++;
} /*add_child */

void remove_child(int parentID, int childID)
{
    if(DEBUG3 && debugflag3)
    {
        console("    - remove_childl(): removing child from process table\n");
    }
    int parent = parentID%MAXPROC;
    ProcTable[parent].num_children--;

    if(ProcTable[parent].childProcPtr->pid == childID)
    {
        ProcTable[parent].childProcPtr = ProcTable[parent].childProcPtr->nextSiblingPtr;
    }
    else
    {
        proc_ptr child;
        for(child = ProcTable[parent].childProcPtr; child->nextSiblingPtr != NULL;
            child = child->nextSiblingPtr)
        {
            if(child->nextSiblingPtr->pid == childID)
            {
                child->nextSiblingPtr = child->nextSiblingPtr->nextSiblingPtr;
                break;
            }
        }
    }
    numProcs--;
} /* remove_child */


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

void setUserMode()
{
    if(DEBUG3 && debugflag3)
        console("    - setUserMode(): inside setUserMode\n");
    psr_set(psr_get() &~PSR_CURRENT_MODE);

    if(DEBUG3 && debugflag3)
        console("        - setUserMode(): user mode set successfully\n");
} /* setUserMode */
