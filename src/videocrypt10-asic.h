/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2017 Philip Heron <phil@sanslogic.co.uk>                    */
/* Copyright 2026 Katy Coe - https://github.com/djkaty/                  */
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

/*=======================================================================*/
/* All of the code in this file belongs to Katy Coe who has worked for   */
/* 999 days (no, really!) to reverse engineer the ASIC used in these     */
/* cards. Without her, this functionality would not have been possible   */
/*=======================================================================*/

#ifndef _VIDEOCRYPT10_ASIC_H
#define _VIDEOCRYPT10_ASIC_H

#include "videocrypt10-ca.h"

extern void asic_reset(asic10_t *asic);
extern void asic_send(asic10_t *asic, const uint8_t *data, int len);
extern void asic_send_from_decoder(asic10_t *asic, const uint8_t *data, int len);
extern uint8_t asic_receive_one(asic10_t *asic);

#endif /* _VIDEOCRYPT10_ASIC_H */