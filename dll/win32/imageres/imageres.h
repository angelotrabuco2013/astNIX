/*
 * PROJECT:     ReactOS imageres.dll
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     imageres.dll
 * COPYRIGHT:   Copyright 2023 Ethan Rodensky <splitwirez@gmail.com>
 */

#ifndef _IMAGERES_H_
#define _IMAGERES_H_

#include <windows.h>

/* Icons */
// TODO: Should this be defined somewhere else, so explorer can use the `IDI_SHOW_DESKTOP` constant?
#define IDI_SHOW_DESKTOP            110 // Why 110? Refer to `dll/win32/imageres/imageres.h`.

#endif /* _IMAGERES_H_ */
