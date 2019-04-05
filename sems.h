//header file
#define DEBUG3 1

typedef struct proc_struct proc_struct;
typedef struct proc_struct * proc_ptr;
typedef struct semStruct semaphore;
typedef struct semStruct * sem_ptr;

struct proc_struct {
   short          pid;               /* process id */
   int            status;         /* READY, BLOCKED, QUIT, etc. */
   int            cur_startTime;
   int            mbox_id;
   char           message[MAX_MESSAGE];
   int            size;
   /* other fields as needed... */
};

struct semStruct{
    //fields as needed
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
