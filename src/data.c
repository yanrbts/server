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
#include "data.h"
#include <math.h>
#include <ctype.h>

Kobject *createObject(int type, void *ptr) {
    Kobject *o = zmalloc(sizeof(*o));
    o->type = type;
    o->ptr = ptr;

    return o;
}

Kobject *createMachineObject(void) {
    Kmachine *km = createMachine();
    Kobject *o = createObject(OBJ_MACHINE, km);
    return o;
}

Kobject *createUserObject(void) {
    Kuser *u = createUser();
    Kobject *o = createObject(OBJ_USE, u);
    return o;
}

Kobject *createFileObject(void) {
    Kfile *f = createFile();
    Kobject *o = createObject(OBJ_FILE, f);
    return o;
}

Kmachine *createMachine(void) {
    Kmachine *km = zmalloc(sizeof(*km));
    km->users = listCreate();
    km->uuid = 0;
    return km;
}

Kuser *createUser(void) {
    Kuser *u = zmalloc(sizeof(*u));
    u->files = listCreate();
    u->name = NULL;
    u->pmch = NULL;
    return u;
}

Kfile *createFile(void) {
    Kfile *f = zmalloc(sizeof(*f));
    f->applynum = 0;
    f->authnum = 0;
    f->filename = NULL;
    f->user = NULL;
    f->uuid = 0;
    return f;
}

