/*
 * Copyright 2024-2024 yanruibinghxu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __DATA_H__
#define __DATA_H__

#include "server.h"

/* The actual Object */
#define OBJ_MACHINE 0   /* Querying encrypted files on the entire machine is generally not used.*/
#define OBJ_USE 1       /* Query all encrypted files of a user */
#define OBJ_FILE 2      /* Query a single encrypted file */

#define LRU_BITS 24
#define LRU_CLOCK_MAX ((1<<LRU_BITS)-1) /* Max value of obj->lru */
#define LRU_CLOCK_RESOLUTION 1000 /* LRU clock resolution in ms */

typedef struct Kuser Kuser;
typedef struct Kmachine Kmachine;

typedef struct Kfile {
    sds filename;               /* file name */
    char fullpath[PATH_MAX];    /* Full file path */
    sds uuid;                   /* file uuid */
    uint64_t applynum;          /* Number of applications */
    uint64_t authnum;           /* Number of authorizations */
    Kuser *user;                /* Pointer to Kuser struct */
} Kfile;

struct Kuser {
    sds name;           /* user name */
    list *files;        /* Current user's file list */
    Kmachine *pmch;     /* User's machine */
};

struct Kmachine {
    sds uuid;
    list *users;
};

typedef struct Kobject {
    unsigned type:4;        /* data type */
    /* unsigned lru:LRU_BITS; LRU time (relative to global lru_clock) or
                            * LFU data (least significant 8 bits frequency
                            * and most significant 16 bits access time). */
    void *ptr;              /* data pointer */
} Kobject;

Kobject *createObject(int type, void *ptr);
Kobject *createMachineObject(void);
Kobject *createUserObject(void);
Kobject *createFileObject(void);

Kmachine *createMachine(void);
void freeMachine(Kmachine *m);
Kuser *createUser(void);
void freeUser(Kuser *u);
Kfile *createFile(void);
void freeFile(Kfile *f);

int api_encrypt_file(cJSON *root, kxykDb *db);

#endif