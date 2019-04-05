//header file
#define DEBUG3 1
#define UNUSED -1

typedef struct proc_struct proc_struct;
typedef struct proc_struct * proc_ptr;
typedef struct semStruct semaphore;
typedef struct semStruct * sem_ptr;

struct proc_struct {
   short          pid;               /* process id */
   short          ppid;
   char           name[MAXNAME];
   char           startArg[MAXARG];
   int            priority;
   int (*start_func) (char *);
   int            stack_size;
   int            spawnBox;
   int            num_children;
   proc_ptr       childProcPtr;
   proc_ptr       nextSiblingPtr;
   /* other fields as needed... */
};

struct semStruct{
    int           mutexBox;
    int           blockedBox;
    int          value;
    int           blocked;
};

struct psr_bits {
    unsigned int cur_mode:1;
    unsigned int cur_int_enable:1;
    unsigned int prev_mode:1;
    unsigned int prev_int_enable:1;
    unsigned int unused:28;
};

union psr_values {
   struct psr_bits bits;
   unsigned int integer_part;
};
