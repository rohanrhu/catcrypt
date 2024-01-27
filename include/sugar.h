/*
 * Catcrypt, simple RSA/PKE for C
 * Copyright (C) 2023, Oğuzhan Eroğlu <meowingcate@gmail.com> (https://meowingcat.io)
 * Licensed under GPLv3 License
 * See LICENSE for more info
 */

#pragma once

#define VARCAT(left, right) left##right

#define LIST_FOREACH(list, node) { \
    int VARCAT(node, _i) = -1; \
    __typeof__(list->next) _##node = list->next; \
    while (_##node) { \
        VARCAT(node, _i)++; \
        __typeof__(list->next) node = _##node; \
        _##node = (_##node)->next;

#define END_FOREACH \
    }}

#define LISTIFY(type) \
    int length; \
    type next; \
    type prev; \
    type terminal;

#define ITEMIFY(type) \
    type next; \
    type prev;

#define LIST_INIT(list) \
    list->prev = NULL; \
    list->next = NULL; \
    list->terminal = NULL; \
    list->length = 0;

#define LIST_APPEND(list, node) \
    if (!list->next) { \
        list->next = node; \
    } \
    \
    node->prev = list->terminal; \
    if (list->terminal) { \
        list->terminal->next = node; \
    } \
    list->terminal = node; \
    \
    list->length++;

#define LIST_REMOVE(list, node) \
    if (list->terminal == node) { \
        list->terminal = node->next \
                       ? node->next \
                       : node->prev; \
    } \
    if (list->next == node) { \
        list->next = node->next; \
    } \
    \
    if (node->next) { \
        node->next->prev = node->prev; \
    } \
    \
    if (node->prev) { \
        node->prev->next = node->next; \
    } \
    list->length--;

#define R(expr) CATCRYPT_REF_BY(expr)