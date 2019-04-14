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

#define debugflag3 0

semaphore 	running;


/* PROTOTYPES */
extern int start3(char *);

int start2(char *);
int  spawn_real(char *name, int (*func)(char *), char *arg,
                int stack_size, int priority);
void wait(sysargs *args);
int  wait_real(int *status);
void spawn(sysargs *args);
void terminate(sysargs *args);
void terminate_real(int status);
void add_child(int child_ID, int parent_ID);
int spawn_launch(char *arg);
void remove_child(int child_ID, int parent_ID);
void clear_proc(int status);
void nullsys3(sysargs *args);

/* Semaphore Prototypes */
void sem_create(sysargs *args);
int sem_create_real(int semID);
void sem_p(sysargs *args);
int sem_p_real(int semID);
void sem_v(sysargs *args);
int sem_v_real(int semID);
void sem_free(sysargs *args);
int sem_free_real(int semID);
int next_sem();

/* Time Prototypes */
void getTimeofDay(sysargs *args);
int getTimeofDay_real();
void cpuTime(sysargs *args);
int cpuTime_real();

int new_getpid(sysargs *args);
static void check_kernel_mode(char *caller_name);
void setUserMode();

semaphore SemTable[MAXSEMS];
proc_struct ProcTable[MAXPROC];


int numProcs = 0;
int Sems = 0;

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
     for(int i = 0; i < MAXSYSCALLS; i++)
     {
       sys_vec[i] = nullsys3;
     }

     sys_vec[SYS_SPAWN] = spawn;
     sys_vec[SYS_WAIT] = wait;
     sys_vec[SYS_TERMINATE] = terminate;
     sys_vec[SYS_SEMCREATE] = sem_create;
     sys_vec[SYS_SEMP] = sem_p;
     sys_vec[SYS_SEMV] = sem_v;
     sys_vec[SYS_SEMFREE] = sem_free;
     sys_vec[SYS_GETPID] = new_getpid;
     sys_vec[SYS_CPUTIME] = cpuTime;
     sys_vec[SYS_GETTIMEOFDAY] = getTimeofDay;

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

void nullsys3(sysargs *args)
{
  if(DEBUG3 && debugflag3)
  {
    console("  - nullsys(): process %d\n", getpid());
  }
  console("    - nullsys(): Invalid syscall %d. Halting...\n", args->number);
  terminate_real(1);
}

void wait(sysargs *args)
{
    if(DEBUG3 && debugflag3)
    {
        console("    - wait(): wait reached\n");
    }
    int status = (int)args->arg2;

    int pid = wait_real(&status);

    args->arg1 = (void *)pid;
    args->arg2 = (void *)status;
    args->arg4 = 0;

    if(is_zapped())
    {
        if(DEBUG3 && debugflag3)
            console("        - wait(): process is zapped. Calling terminate_real()\n");
        terminate_real(1);
    }
}

int  wait_real(int *status)
{
    if(DEBUG3 && debugflag3)
        console("    - wait_real(): Entering function.\n");
    int result = join(status);

    return result;
} /* wait_real */

void spawn(sysargs *args)
{
    if(DEBUG3 && debugflag3)
    {
        console("    - spawn(): spawn reached\n");
    }

   int (*func)(char *) = args->arg1;
   char *arg = args->arg2;
   int stack_size = (int)((long)args->arg3);
   int priority = (int)((long) args->arg4);
   char *name = args->arg5;

   if(func == NULL || stack_size < USLOSS_MIN_STACK || numProcs > MAXPROC)
   {
       if(DEBUG3 && debugflag3)
       {
           console("    - spawn(): invalid arguments. Returning...\n");
       }
       args->arg1 = (void *)UNUSED;
       return;
   }

   int pid = spawn_real(name, func, arg, stack_size, priority);

   args->arg1 = (void *) pid;
   //args->arg4 = (void *) 0;

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
  ProcTable[slot].start_func = func;
  ProcTable[slot].priority = priority;
  numProcs++;

  if(name != NULL)
  {
      memcpy(ProcTable[slot].name, name, strlen(name));
  }

  if(arg != NULL)
  {
      memcpy(ProcTable[slot].startArg, arg, strlen(arg));
  }

  ProcTable[slot].ppid = getpid();

  add_child(pid, getpid());

  if(ProcTable[pid % MAXPROC].priority < ProcTable[getpid() % MAXPROC].priority)
  {
      MboxSend(ProcTable[slot].spawnBox, NULL, 0);
  }

  if(is_zapped())
  {
      if(DEBUG3 && debugflag3)
      {
          console("    - spawn(): process is zapped. Terminating.\n");
      }
      terminate_real(0);
      return 0;
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
        MboxReceive(ProcTable[pid].spawnBox, NULL, 0);
    }

    if(is_zapped())
    {
        terminate_real(0);
        return 0;
    }
    setUserMode();

    result = process->start_func(arg);
    Terminate(result);
    return result;
} /* spawn_launch */


void terminate(sysargs *args)
{
  if(DEBUG3 && debugflag3)
  {
      console("    - terminate(): terminate reached\n");
  }
  int status = (int)(args->arg1);
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

    if(DEBUG3 && debugflag3)
        console("        - terminate_real(): terminating process and children\n");

    if(process.num_children != 0)
    {
        int children[MAXPROC];
        int i = 0;
        proc_ptr child = process.childProcPtr;
        while(child != NULL)
        {
            int pid = child->pid;
            children[i] = pid%MAXPROC;
            child = child->nextSiblingPtr;
            i++;
        }

        for(int j = 0; j < process.num_children; j++)
        {
            console("%d\n", children[j]);
            if(children[j] <= 0)
            {
                if(DEBUG3 && debugflag3)
                    console("        - terminate_real(): invalid pid. returning");
            }
            else
            {
                if(DEBUG3 && debugflag3)
                    console("        - terminate_real(): zapping child %d\n", children[j]);
                remove_child(children[j], process.ppid);
                zap(children[j]);
                if(DEBUG3 && debugflag3)
                    console("        - terminate_real(): Child %d has been zapped\n", children[j]);
            }
        }

    }
    remove_child(getpid(), process.ppid);
    //zap(process.pid);
    clear_proc(getpid()%MAXPROC);
    numProcs--;
    quit(status);
} /*terminate_real */

void sem_create(sysargs *args)
{
    if(DEBUG3 && debugflag3)
    {
      console("    - process %d: sem_create\n", getpid());
    }

    int address = sem_create_real((int)args->arg1);

    if(address == -1)
    {
      args->arg4 = (void *)-1;
      args->arg1 = NULL;
    }
    else
    {
      args->arg4 = 0;
      args->arg1 = (void *) address;
    }
} /* sem_create */

int sem_create_real(int semID)
{
    if(DEBUG3 && debugflag3)
    {
      console("    - process %d: sem_create_real\n", getpid());
    }

    if(Sems >= MAXSEMS)
    {
        if(DEBUG3 && debugflag3)
            console("        - sem_create_real(): Max Semaphores reached.\n");
        return -1;
    }

    int mutexBox = MboxCreate(1, 0);

    if(mutexBox == -1)
    {
        if(DEBUG3 && debugflag3)
            console("        - sem_create_real(): Could not create mutex box.\n");
        return -1;
    }

    int blockedBox = MboxCreate(0, 0);

    if(blockedBox == -1)
    {
        if(DEBUG3 && debugflag3)
            console("        - sem_create_real(): Could not create blocked box.\n");
        return -1;
    }

    int sem_num = next_sem();
    SemTable[sem_num].mutexBox = mutexBox;
    SemTable[sem_num].blockedBox = blockedBox;
    SemTable[sem_num].value = semID;
    SemTable[sem_num].blocked = 0;

    Sems++;

    return sem_num;

} /* sem_create_real */

void sem_p(sysargs *args)
{
    if(DEBUG3 && debugflag3)
        console("    - sem_p(): entering sem_p function.\n");
    int semID, result;

    semID = (int)args->arg1;
    result = sem_p_real(semID);

    args->arg4 = (void *) result;
} /* sem_p */

int sem_p_real(int semID)
{
    if(DEBUG3 && debugflag3)
        console("    - sem_p_real(): entering sem_p_real function.\n");
    int mutexBox, blockedBox;
    int break_loop = 0;

    mutexBox = SemTable[semID].mutexBox;
    blockedBox = SemTable[semID].blockedBox;
    if(mutexBox == -1)
    {
        if(DEBUG3 && debugflag3)
            console("       - sem_p_real(): invalid mutex box.\n");
        return -1;
    }

    MboxSend(mutexBox, NULL, 0);

    do{
        SemTable[semID].blocked++;
        MboxReceive(mutexBox, NULL, 0);

        MboxSend(blockedBox, NULL, 0);

        if(is_zapped())
            terminate_real(0);
        if(mutexBox == -1)
        {
            break_loop = 1;
        }
        else
        {
            MboxSend(mutexBox, NULL, 0);
        }
    }while(SemTable[semID].value <= 0 && break_loop != 1);

    if(break_loop != 1)
    {
        SemTable[semID].value--;
        MboxReceive(mutexBox, NULL, 0);
    }
    else
    {
        terminate_real(1);
    }
    return 0;

} /* sem_p_real */

void sem_v(sysargs *args)
{
    if(DEBUG3 && debugflag3)
        console("    - sem_v(): entering sem_v function.\n");
    int semID = (int)args->arg1;
    int result = sem_v_real(semID);

    args->arg4 = (void *) result;

} /* sem_v */

int sem_v_real(int semID)
{
    if(DEBUG3 && debugflag3)
        console("    - sem_v_real(): entering sem_v_real function.\n");
    int mutexBox, blockedBox;

    mutexBox = SemTable[semID].mutexBox;
    blockedBox = SemTable[semID].blockedBox;

    if(mutexBox == -1)
    {
        if(DEBUG3 && debugflag3)
            console("        - sem_v_real(): Invalid mutexBox.\n");
        return -1;
    }

    MboxSend(mutexBox, NULL, 0);
    SemTable[semID].value++;

    if(SemTable[semID].blocked > 0)
    {
        MboxReceive(blockedBox, NULL, 0);
        SemTable[semID].blocked--;
    }

    MboxReceive(mutexBox, NULL, 0);

    if(is_zapped())
        terminate_real(0);
    return 0;

} /* sem_v_real */

void sem_free(sysargs *args)
{
    if(DEBUG3 && debugflag3)
        console("    - sem_free(): entering sem_free function.\n");
    int result;
    int semID = (int)args->arg1;
    if(semID == -1)
    {
        if(DEBUG3 && debugflag3)
            console("        - sem_free(): invalid semaphore ID. \n");
        args->arg4 = (void *) -1;
    }
    else
    {
        result = sem_free_real(semID);
        args->arg4 = (void *) result;
    }
} /* sem_free */

int sem_free_real(int semID)
{
    if(DEBUG3 && debugflag3)
        console("    - sem_free_real(): entering sem_free_real function.\n");
    if(SemTable[semID].mutexBox == -1)
    {
        if(DEBUG3 && debugflag3)
            console("        - sem_free_real(): invalid mutex box.\n");
        return -1;
    }

    SemTable[semID].mutexBox = -1;
    int result = 0;
    if(DEBUG3 && debugflag3)
        console("        - sem_free_real(): mutexBox reset to -1\n");

    if(SemTable[semID].blocked > 0)
    {
        if(DEBUG3 && debugflag3)
            console("        - sem_free_real(): unblocking processes\n");
        result = -1;
        int loop = SemTable[semID].blocked;
        for(int i = 0; i < loop; i++)
        {
            if(DEBUG3 && debugflag3)
                console("        - sem_free_real(): recieving message %d\n", i);
            MboxReceive(SemTable[semID].blockedBox, NULL, 0);
        }
        if(DEBUG3 && debugflag3)
            console("        - sem_free_real(): processes unblocked.\n");
    }
    SemTable[semID].blockedBox = -1;
    SemTable[semID].value = -1;
    SemTable[semID].blocked = 0;

    MboxRelease(SemTable[semID].mutexBox);
    MboxRelease(SemTable[semID].blockedBox);

    if(is_zapped())
        terminate_real(0);
    Sems--;
    return result;
} /* sem_free_real */

void getTimeofDay(sysargs *args)
{
    int result = getTimeofDay_real();

    args->arg1 = (void *) result;
} /* getTimeofDay */

int getTimeofDay_real()
{
    return sys_clock();
} /* getTimeofDay_real */

void cpuTime(sysargs *args)
{
    int result = cpuTime_real();
    args->arg1 = (void *) result;

} /* cpuTime */

int cpuTime_real()
{
    return readtime();
} /* cpuTime_real */

int next_sem()
{
    while(SemTable[Sems].mutexBox != -1)
    {
        Sems++;
        if(Sems >= MAXSEMS)
        {
            Sems = 0;
        }
    }
    return Sems;
}
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
    ProcTable[slot].num_children = 0;
} /*clear_proc */

void add_child(int child_ID, int parent_ID)
{
    if(DEBUG3 && debugflag3)
    {
        console("    - add_child(): adding child to process table\n");
    }
    parent_ID %= MAXPROC;
    child_ID %= MAXPROC;

    ProcTable[parent_ID].num_children++;

    if(ProcTable[parent_ID].childProcPtr == NULL)
    {
        ProcTable[parent_ID].childProcPtr = &ProcTable[child_ID];
        if(DEBUG3 && debugflag3)
            console("        - add_child(): child process added successfully1\n");
    }
    else
    {
        ProcTable[parent_ID].childProcPtr->nextSiblingPtr = &ProcTable[child_ID];

        if(DEBUG3 && debugflag3)
            console("        - add_child(): child process added successfully2\n");
    }

} /*add_child */

void remove_child(int child_ID, int parent_ID)
{
    //console("%d\n", ProcTable[parent_ID].num_children);
    if(DEBUG3 && debugflag3)
    {
        console("    - remove_child(): removing child from process table\n");
    }

     parent_ID %= MAXPROC;
     //console("%d, %d\n", parent_ID, child_ID);
     if(ProcTable[parent_ID].childProcPtr->pid == child_ID)
     {
        // console(" I got here5\n");
         if(DEBUG3 && debugflag3)
            console("        - remove_child(): removing child...\n");
         ProcTable[parent_ID].childProcPtr = ProcTable[parent_ID].childProcPtr->nextSiblingPtr;
         ProcTable[parent_ID].num_children--;
     }
     else if(ProcTable[parent_ID].childProcPtr != NULL)
     {
         //console("I got here blah\n");
         proc_ptr child = ProcTable[parent_ID].childProcPtr;
         if(child->nextSiblingPtr == NULL)
         {
            // console(" I got here9\n");
             return;
             //ProcTable[parent_ID].childProcPtr = NULL;
         }
         while(child->nextSiblingPtr != NULL)
         {
             if(DEBUG3 && debugflag3)
                console("        - remove_child(): locating child to remove...\n");
        //     console(" I got here\n");
             if(child->nextSiblingPtr->pid == child_ID)
             {
        //         console(" I got here2\n");
                 if(DEBUG3 && debugflag3)
                    console("        - remove_child(): child located. Removing...\n");

                 child->nextSiblingPtr = child->nextSiblingPtr->nextSiblingPtr;
             }
             else {
        //         console(" I got here3\n");
                 child = child->nextSiblingPtr;
             }
         }
         ProcTable[parent_ID].num_children--;
     }
     else
     {
         //console("here\n");

     }
     //console(" I got here4\n");

    // console("%d\n", ProcTable[parent_ID].num_children);
} /* remove_child */

int new_getpid(sysargs *args)
{
    int result = getpid();
    args->arg1 = (void *) result;
    return result;
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

void setUserMode()
{
    if(DEBUG3 && debugflag3)
        console("    - setUserMode(): inside setUserMode\n");
    psr_set(psr_get() &~PSR_CURRENT_MODE);

    if(DEBUG3 && debugflag3)
        console("        - setUserMode(): user mode set successfully\n");
} /* setUserMode */
