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
    km->uuid = sdsempty();
    return km;
}

Kuser *createUser(void) {
    Kuser *u = zmalloc(sizeof(*u));
    u->files = listCreate();
    u->name = sdsempty();
    u->pmch = NULL;
    return u;
}

Kfile *createFile(void) {
    Kfile *f = zmalloc(sizeof(*f));
    f->applynum = 0;
    f->authnum = 0;
    f->filename = sdsempty();
    f->user = NULL;
    f->uuid = sdsempty();
    return f;
}

/*--------------------------------API FUNCTION-------------------------------------*/

int api_encrypt_file(cJSON *root, kxykDb *db) {
    int ret = 0;
    cJSON *jk, *ju, *jf;
    Kmachine *km;
    Kuser *ku;
    Kfile *kf = NULL;
    Kobject *o;

    /* machine */
    jk = cJSON_GetObjectItem(root, "machine");
    if (cJSON_IsString(jk) && (jk->valuestring != NULL)) {
        km = createMachine();
        km->uuid = sdscpy(km->uuid, jk->valuestring);
    } else {
        serverLog(LL_RAW, "encry file machine node format is incorrect");
        ret = -1;
        goto err;
    }

    /* user */
    ju = cJSON_GetObjectItem(root, "user");
    if (cJSON_IsString(ju) && (ju->valuestring != NULL)) {
        ku = createUser();
        ku->name = sdscpy(ku->name, ju->valuestring);
    } else {
        serverLog(LL_RAW, "encry file user node format is incorrect");
        ret = -1;
        goto err;
    }
    /* files */
    jf = cJSON_GetObjectItem(root, "file");
    if (cJSON_IsArray(jf)) {
        int count = cJSON_GetArraySize(jf);

        for (int i = 0; i < count; i++) {
            kf = createFile();
            cJSON *file_object = cJSON_GetArrayItem(jf, i);
            cJSON *filename = cJSON_GetObjectItem(file_object, "filename");
            if (cJSON_IsString(filename) && (filename->valuestring != NULL)) {
                kf->filename = sdscpy(kf->filename, filename->valuestring);
            }

            cJSON *uuid = cJSON_GetObjectItem(file_object, "uuid");
            if (cJSON_IsString(uuid) && (uuid->valuestring != NULL)) {
                kf->uuid = sdscpy(kf->uuid, uuid->valuestring);
            }

            if (kf->filename && kf->uuid)
                listAddNodeHead(ku->files, kf);
        }
    } else {
        ret = -1;
        goto err;
    }

    listAddNodeHead(km->users, ku);
    
    o = createObject(OBJ_MACHINE, km);
    dictAdd(db->dict, &km->uuid, o);

    return ret;
err:
    return ret;
}