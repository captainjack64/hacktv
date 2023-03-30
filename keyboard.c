/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2017 Philip Heron <phil@sanslogic.co.uk>                    */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* (at your option) any later version.                                   */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include "keyboard.h"

struct termios trm;

void kb_enable()
{
    tcgetattr(0, &trm);
    trm.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(0, TCSANOW, &trm);
}

void kb_disable()
{
    tcgetattr(0, &trm);
    trm.c_lflag |= ICANON | ECHO;
    tcsetattr(0, TCSANOW, &trm);
}

#ifndef WIN32
int kbhit()
{
    int byteswaiting;
    ioctl(0, FIONREAD, &byteswaiting);
    return byteswaiting > 0;
}
#endif
