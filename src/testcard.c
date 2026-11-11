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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "testcard.h"
#include "testcard_glyphs.h"

/* Horizontal supersampling factor */
#define TC_SS 4

/* Reference PAL timing used to describe the cards */
#define TC_REF_ACTIVE_LEFT  10.40  /* µs */
#define TC_REF_ACTIVE_WIDTH 51.95  /* µs */
#define TC_REF_LINES        576.0

typedef struct {
	float y, u, v;
} yuv_t;

typedef struct {
	int w;          /* Output width in pixels */
	int h;          /* Output height in lines */
	int sw;         /* Supersampled width */
	double *t;      /* Card time of each subsample (µs) */
	double rscale;  /* Card rows per output line */
	float *Y, *U, *V;
	const testcard_image_t *logo;

	/* Circle clip */
	double c_ct;    /* Centre in µs */
	double c_rt;    /* Radius in µs */
	double c_rr;    /* Radius in rows */
	double c_cr;    /* Centre row */
	double c_soft;  /* Edge softness (fraction of radius) */
} tc_t;

/* Clip modes */
#define TC_NOCLIP 0
#define TC_INSIDE 1
#define TC_OUTSIDE 2

/* Helpers to build colours */
static yuv_t _yuv(double y, double u, double v)
{
	return (yuv_t) { y, u, v };
}

static yuv_t _rgb(double r, double g, double b)
{
	double y = 0.299 * r + 0.587 * g + 0.114 * b;
	return (yuv_t) { y, (b - y) * 0.493, (r - y) * 0.877 };
}

static yuv_t _grey(double l)
{
	return (yuv_t) { l, 0, 0 };
}

/* Card row (centre) of output line y */
static double _row(tc_t *tc, int y)
{
	return (y + 0.5) * tc->rscale;
}

static int _odd_line(int y)
{
	return (y & 3) == 0 || (y & 3) == 3;
}

static double _circle_alpha(tc_t *tc, double t, double r)
{
	double a, b, rho;

	a = (t - tc->c_ct) / tc->c_rt;
	b = (r - tc->c_cr) / tc->c_rr;
	rho = sqrt(a * a + b * b);

	a = 0.5 - (rho - 1.0) / tc->c_soft;

	return(a < 0 ? 0 : (a > 1 ? 1 : a));
}

/* Find the range of output lines covering card rows r0 to r1 */
static void _rows(tc_t *tc, double r0, double r1, int *y0, int *y1)
{
	*y0 = ceil(r0 / tc->rscale - 0.5);
	*y1 = ceil(r1 / tc->rscale - 0.5);
	if(*y0 < 0) *y0 = 0;
	if(*y1 > tc->h) *y1 = tc->h;
}

/* Find the range of subsamples covering card time t0 to t1 */
static void _cols(tc_t *tc, double t0, double t1, int *x0, int *x1)
{
	double d = tc->t[1] - tc->t[0];
	*x0 = ceil((t0 - tc->t[0]) / d);
	*x1 = ceil((t1 - tc->t[0]) / d);
	if(*x0 < 0) *x0 = 0;
	if(*x1 > tc->sw) *x1 = tc->sw;
}

static void _blend(tc_t *tc, int i, yuv_t c, double a)
{
	if(a >= 1.0)
	{
		tc->Y[i] = c.y;
		tc->U[i] = c.u;
		tc->V[i] = c.v;
	}
	else if(a > 0.0)
	{
		tc->Y[i] += (c.y - tc->Y[i]) * a;
		tc->U[i] += (c.u - tc->U[i]) * a;
		tc->V[i] += (c.v - tc->V[i]) * a;
	}
}

static double _clip_alpha(tc_t *tc, int clip, double t, double r)
{
	if(clip == TC_INSIDE) return(_circle_alpha(tc, t, r));
	if(clip == TC_OUTSIDE) return(1.0 - _circle_alpha(tc, t, r));
	return(1.0);
}

/* Fill a rectangle. Two colours can be given for alternating lines */
static void _rect2(tc_t *tc, double t0, double t1, double r0, double r1, yuv_t odd, yuv_t even, int clip)
{
	int x, y, x0, x1, y0, y1;
	double r;

	_rows(tc, r0, r1, &y0, &y1);
	_cols(tc, t0, t1, &x0, &x1);

	for(y = y0; y < y1; y++)
	{
		yuv_t c = _odd_line(y) ? odd : even;
		r = _row(tc, y);

		for(x = x0; x < x1; x++)
		{
			_blend(tc, y * tc->sw + x, c, _clip_alpha(tc, clip, tc->t[x], r));
		}
	}
}

static void _rect(tc_t *tc, double t0, double t1, double r0, double r1, yuv_t c, int clip)
{
	_rect2(tc, t0, t1, r0, r1, c, c, clip);
}

/* Line-alternating colour difference (PAL switch test) */
static void _alt(tc_t *tc, double t0, double t1, double r0, double r1, double y, double u, double v, int clip)
{
	_rect2(tc, t0, t1, r0, r1, _yuv(y, -u, -v), _yuv(y, u, v), clip);
}

/* Vertical line of width w centred on t */
static void _vline(tc_t *tc, double t, double w, double r0, double r1, yuv_t c, int clip)
{
	_rect(tc, t - w / 2, t + w / 2, r0, r1, c, clip);
}

/* Sine wave grating: luma = mean + amp * sin(2 pi f t + phase) */
static void _grating(tc_t *tc, double t0, double t1, double r0, double r1, double f, double phase, double mean, double amp, int clip)
{
	int x, y, x0, x1, y0, y1;
	double r;

	_rows(tc, r0, r1, &y0, &y1);
	_cols(tc, t0, t1, &x0, &x1);

	for(y = y0; y < y1; y++)
	{
		r = _row(tc, y);

		for(x = x0; x < x1; x++)
		{
			double t = tc->t[x - x % TC_SS] + (tc->t[1] - tc->t[0]) * (TC_SS - 1) / 2;
			double l = mean + amp * sin(2.0 * M_PI * f * t + phase);
			_blend(tc, y * tc->sw + x, _grey(l), _clip_alpha(tc, clip, tc->t[x], r));
		}
	}
}

static void _glyph(tc_t *tc, const tc_glyph_t *g, double t0, double r0, double pt, double pr, yuv_t c)
{
	int x, y, x0, x1, y0, y1;

	_rows(tc, r0, r0 + g->h * pr, &y0, &y1);
	_cols(tc, t0, t0 + g->w * pt, &x0, &x1);

	for(y = y0; y < y1; y++)
	{
		/* Mask coordinates, bilinear interpolation */
		double my = (_row(tc, y) - r0) / pr - 0.5;
		int iy = floor(my);
		double fy = my - iy;

		for(x = x0; x < x1; x++)
		{
			double mx = (tc->t[x] - t0) / pt - 0.5;
			int ix = floor(mx);
			double fx = mx - ix;
			double a = 0;
			int i, j;

			for(j = 0; j < 2; j++)
			{
				for(i = 0; i < 2; i++)
				{
					int px = ix + i;
					int py = iy + j;
					double w = (i ? fx : 1 - fx) * (j ? fy : 1 - fy);

					if(px < 0 || py < 0 || px >= g->w || py >= g->h) continue;
					a += w * g->data[py * g->w + px] / 255.0;
				}
			}

			_blend(tc, y * tc->sw + x, c, a);
		}
	}
}

/* Place a glyph within a box centred on t, r, keeping its original offset */
static void _glyph_c(tc_t *tc, const tc_glyph_t *g, double t, double r, double pt, double pr, yuv_t c)
{
	t += g->cx * pt;
	r += g->cy * pr;
	_glyph(tc, g, t - g->w * pt / 2, r - g->h * pr / 2, pt, pr, c);
}

/* Pixel size of the original 768 x 576 (4:3) / 1024 x 576 (16:9) artwork */
#define ART_43  (TC_REF_ACTIVE_WIDTH / 768.0)
#define ART_169 (TC_REF_ACTIVE_WIDTH / 1024.0)

/* HACK TV logo, scaled to fit the box. art is the square pixel width in µs */
static void _logo(tc_t *tc, double t0, double t1, double r0, double r1, double art)
{
	const testcard_image_t *img = tc->logo;
	double pt, pr, lt, lr;
	int x, y, x0, x1, y0, y1;
	
	if(!img) return;
	
	pt = (t1 - t0) / img->width;
	pr = pt / art;
	
	if(img->height * pr > r1 - r0)
	{
		pr = (r1 - r0) / img->height;
		pt = pr * art;
	}
	
	/* Extend the logo's own box to fill the text box */
	_rect(tc, t0, t1, r0, r1, _grey(0.0), TC_NOCLIP);
	_rect(tc, t0 + (t1 - t0) * 0.65, t1, r0, r1, _grey(90 / 255.0), TC_NOCLIP);
	
	lt = (t0 + t1) / 2 - img->width * pt / 2;
	lr = (r0 + r1) / 2 - img->height * pr / 2;
	
	_rows(tc, lr, lr + img->height * pr, &y0, &y1);
	_cols(tc, lt, lt + img->width * pt, &x0, &x1);
	
	for(y = y0; y < y1; y++)
	{
		double my = (_row(tc, y) - lr) / pr - 0.5;
		int iy = floor(my);
		double fy = my - iy;
		
		for(x = x0; x < x1; x++)
		{
			double mx = (tc->t[x] - lt) / pt - 0.5;
			int ix = floor(mx);
			double fx = mx - ix;
			double c[3] = { 0, 0, 0 }, wsum = 0;
			int i, j, k;
			
			for(j = 0; j < 2; j++)
			{
				for(i = 0; i < 2; i++)
				{
					int px = ix + i < 0 ? 0 : (ix + i >= img->width ? img->width - 1 : ix + i);
					int py = iy + j < 0 ? 0 : (iy + j >= img->height ? img->height - 1 : iy + j);
					double w = (i ? fx : 1 - fx) * (j ? fy : 1 - fy);
					uint32_t p = img->data[py * img->width + px];
					
					for(k = 0; k < 3; k++) c[k] += w * ((p >> (16 - k * 8)) & 0xFF) / 255.0;
					wsum += w;
				}
			}
			
			_blend(tc, y * tc->sw + x, _rgb(c[0] / wsum, c[1] / wsum, c[2] / wsum), 1.0);
		}
	}
}

/*** Philips PM5544 / PM5644 ***/

typedef struct {
	double p;               /* Grid pitch, µs */
	double lw;              /* Line width, µs */
	double edge;            /* Grid columns either side of centre before the side castellations */
	int cast_odd;           /* Top and bottom castellations: 1 = odd columns are white */
	double thin;            /* Position of the reflection check lines, µs */
	double phase[5];        /* Grating phases */
	double art;             /* Square pixel width, µs */
} philips_t;

static void _philips(tc_t *tc, const philips_t *ph)
{
	const double P = ph->p;
	const double w = ph->lw;
	const double grey = 0.48;
	const double f[5] = { 0.8, 1.8, 2.8, 3.8, 4.8 };
	int k;
	
	/* Circle: 6 grid squares in radius */
	tc->c_rt = 6 * P;
	tc->c_rr = 252;
	tc->c_cr = 288;
	tc->c_soft = 0.0086;
	
	/* Background */
	_rect(tc, -1e3, 1e3, -1e3, 1e3, _grey(grey), TC_NOCLIP);
	
	/* Castellations, top and bottom (by column) and sides (by row) */
	for(k = -14; k <= 14; k++)
	{
		yuv_t c = _grey((k & 1) == ph->cast_odd ? 1.0 : 0.0);
		_rect(tc, (k - 0.5) * P, (k + 0.5) * P, 0, 14, c, TC_NOCLIP);
		_rect(tc, (k - 0.5) * P, (k + 0.5) * P, 562, 576, c, TC_NOCLIP);
	}
	
	for(k = -6; k <= 6; k++)
	{
		yuv_t c = _grey(k & 1 ? 1.0 : 0.0);
		_rect(tc, -1e3, -ph->edge * P, 288 + (k - 0.5) * 42, 288 + (k + 0.5) * 42, c, TC_NOCLIP);
		_rect(tc, ph->edge * P, 1e3, 288 + (k - 0.5) * 42, 288 + (k + 0.5) * 42, c, TC_NOCLIP);
	}
	
	if(ph->edge < 9)
	{
		/* PM5544: PAL switch test on the left border */
		_alt(tc, -1e3, -8.5 * P - w / 2, 100, 140, 0.0, 0.0, 0.235, TC_NOCLIP);
		
		/* Line alternating ±(R-Y) and ±(B-Y) columns */
		_alt(tc, -8.5 * P + w / 2, -7.5 * P - w / 2, 36, 540, grey, 0.0, 0.235, TC_NOCLIP);
		_alt(tc, 7.5 * P + w / 2, 8.5 * P - w / 2, 36, 540, grey, 0.235, 0.0, TC_NOCLIP);
	}
	else
	{
		/* PM5644: line alternating ±(R-Y) and ±(B-Y) patches */
		_alt(tc, -11.5 * P + w / 2, -10.5 * P - w / 2, 202, 266, grey, 0.0, 0.24, TC_NOCLIP);
		_alt(tc, 10.5 * P + w / 2, 11.5 * P - w / 2, 202, 266, grey, 0.24, 0.0, TC_NOCLIP);
	}
	
	/* Grid lines */
	for(k = -14; k < 14; k++)
	{
		_vline(tc, (k + 0.5) * P, w, -1e3, 1e3, _grey(1.0), TC_NOCLIP);
	}
	
	for(k = 0; k < 14; k++)
	{
		_rect(tc, -1e3, 1e3, 14 + k * 42, 16 + k * 42, _grey(1.0), TC_NOCLIP);
	}
	
	/* R-Y and B-Y bars */
	_rect(tc, -7.5 * P + w / 2, -6.5 * P - w / 2, 58, 288, _yuv(grey, 0, -0.235), TC_NOCLIP);
	_rect(tc, -7.5 * P + w / 2, -6.5 * P - w / 2, 288, 518, _yuv(grey, 0, 0.235), TC_NOCLIP);
	_rect(tc, 6.5 * P + w / 2, 7.5 * P - w / 2, 58, 288, _yuv(grey, -0.235, 0), TC_NOCLIP);
	_rect(tc, 6.5 * P + w / 2, 7.5 * P - w / 2, 288, 518, _yuv(grey, 0.235, 0), TC_NOCLIP);
	
	/* G-Y rectangles */
	_rect(tc, -6.5 * P - w / 2, -5.5 * P - w / 2, 58, 140, _yuv(grey, 0.1942, -0.1319), TC_NOCLIP);
	_rect(tc, -6.5 * P - w / 2, -5.5 * P - w / 2, 436, 518, _yuv(grey, -0.1942, 0.1319), TC_NOCLIP);
	_rect(tc, 5.5 * P + w / 2, 6.5 * P + w / 2, 58, 140, _yuv(grey, 0.1942, -0.1319), TC_NOCLIP);
	_rect(tc, 5.5 * P + w / 2, 6.5 * P + w / 2, 436, 518, _yuv(grey, -0.1942, 0.1319), TC_NOCLIP);
	
	/* Inside the circle */
	
	/* White top, text box */
	_rect(tc, -1e3, 1e3, 0, 98, _grey(1.0), TC_INSIDE);
	_rect(tc, -2 * P, 2 * P, 56, 98, _grey(0.0), TC_INSIDE);
	
	/* Reflection check */
	_rect(tc, -1e3, 1e3, 98, 140, _grey(0.0), TC_INSIDE);
	_rect(tc, -3 * P, 3 * P, 98, 140, _grey(1.0), TC_INSIDE);
	_vline(tc, ph->thin, w, 98, 140, _grey(0.0), TC_INSIDE);
	
	/* 250 kHz square wave */
	for(k = -10; k < 10; k++)
	{
		_rect(tc, k * 2.0, (k + 1) * 2.0, 140, 182, _grey(k & 1 ? 0.75 : 0.0), TC_INSIDE);
	}
	
	/* Colour bars */
	_rect(tc, -1e3, -4 * P, 182, 268, _rgb(0.75, 0.75, 0.00), TC_INSIDE);
	_rect(tc, -4 * P, -2 * P, 182, 268, _rgb(0.00, 0.75, 0.75), TC_INSIDE);
	_rect(tc, -2 * P, 0 * P, 182, 268, _rgb(0.00, 0.75, 0.00), TC_INSIDE);
	_rect(tc, 0 * P, 2 * P, 182, 268, _rgb(0.75, 0.00, 0.75), TC_INSIDE);
	_rect(tc, 2 * P, 4 * P, 182, 268, _rgb(0.75, 0.00, 0.00), TC_INSIDE);
	_rect(tc, 4 * P, 1e3, 182, 268, _rgb(0.00, 0.00, 0.75), TC_INSIDE);
	
	/* Black band with the grid continued through it */
	_rect(tc, -1e3, 1e3, 268, 308, _grey(0.0), TC_INSIDE);
	
	for(k = -10; k < 10; k++)
	{
		_vline(tc, (k + 0.5) * P, w, 268, 308, _grey(1.0), TC_INSIDE);
	}
	
	/* Gratings: 0.8, 1.8, 2.8, 3.8 and 4.8 MHz */
	_rect(tc, -1e3, 1e3, 308, 392, _grey(0.0), TC_INSIDE);
	
	for(k = 0; k < 5; k++)
	{
		_grating(tc, (k * 2 - 5) * P, (k * 2 - 3) * P, 308, 392, f[k], ph->phase[k], 0.5, 0.5, TC_INSIDE);
	}
	
	/* Grey scale */
	for(k = 0; k < 6; k++)
	{
		_rect(tc, k == 0 ? -1e3 : (k * 2 - 6) * P, k == 5 ? 1e3 : (k * 2 - 4) * P, 392, 434, _grey(k * 0.2), TC_INSIDE);
	}
	
	/* Lower text box with reflection check */
	_rect(tc, -1e3, 1e3, 434, 476, _grey(1.0), TC_INSIDE);
	_rect(tc, -3 * P, 3 * P, 434, 476, _grey(0.0), TC_INSIDE);
	_vline(tc, ph->thin, w, 434, 476, _grey(1.0), TC_INSIDE);
	
	/* Yellow / red colour step */
	_rect(tc, -1e3, 1e3, 476, 1e3, _rgb(0.75, 0.75, 0.00), TC_INSIDE);
	_rect(tc, -(0.5 * P - w / 2), 0.5 * P - w / 2, 476, 1e3, _rgb(0.75, 0.00, 0.00), TC_INSIDE);
	
	/* Centre cross */
	_rect(tc, -(0.5 * P - w / 2), 0.5 * P - w / 2, 224, 350, _grey(0.0), TC_INSIDE);
	_vline(tc, 0, w, 224, 350, _grey(1.0), TC_INSIDE);
	_rect(tc, -1e3, 1e3, 287, 289, _grey(1.0), TC_INSIDE);
	
	/* HACK TV logo in the upper text box */
	_logo(tc, -2 * P, 2 * P, 56, 98, ph->art);
}

static void _pm5544(tc_t *tc)
{
	const philips_t ph = {
		.p = 2.8463,
		.lw = 0.2250,
		.edge = 8.5,
		.cast_odd = 1,
		.thin = -7.0927,
		.phase = { 2.4826, -0.3435, -1.3059, -0.3502, 2.4725 },
		.art = ART_43,
	};
	
	_philips(tc, &ph);
}

static double _wheel_luma(double u, double v, double lx, double ly)
{
	const double k = 0.0705;   /* Angular pitch of the wedge lines */
	const double d = 0.81;     /* Distance of the wedge vanishing point beyond the centre */
	double r = sqrt(u * u + v * v);
	double a, s, l;
	int i;
	
	if(r >= 1.535) return(-1);
	
	/* Outer ring */
	if(r >= 1.465) return(1.0);
	
	/* Centre rings */
	if(fabs(r - 0.318) < 0.0225 || fabs(r - 0.408) < 0.0225 || fabs(r - 0.498) < 0.0225) return(1.0);
	
	if(r < 0.525) return(0.0);
	
	/* Wedges, horizontal and vertical */
	s = fabs(u) > fabs(v) ? v / (fabs(u) + d) : u / (fabs(v) + d);
	
	for(i = -2; i <= 2; i++)
	{
		if(fabs(s - i * k) < k / 4)
		{
			/* Gaps in the centre line at the marked radii */
			if(i == 0 && (fabs(r - 0.835) < 0.03 || fabs(r - 1.165) < 0.03)) return(0.0);
			return(1.0);
		}
	}
	
	/* Scale arcs, broken where the labels are */
	a = atan2(v * ly, u * lx) * 180.0 / M_PI;   /* 45 degrees points at the "20" label */
	l = fabs(a - 45.0);
	
	if(fabs(r - 1.172) < 0.035 && l >= 12 && l <= 27) return(1.0);
	
	a = atan2(-v * ly, -u * lx) * 180.0 / M_PI;  /* 45 degrees points at the "35" label */
	l = fabs(a - 45.0);
	
	if(fabs(r - 0.828) < 0.035 && a <= 45.0 - 11 && a >= 45.0 - 28) return(1.0);
	
	return(0.0);
}

static void _wheel(tc_t *tc, double P, double cx, double cy, int lx, int ly)
{
	int x, y, x0, x1, y0, y1, j;
	const double R = 1.6;
	
	_rows(tc, cy - R * 42, cy + R * 42, &y0, &y1);
	_cols(tc, cx - R * P, cx + R * P, &x0, &x1);
	
	for(y = y0; y < y1; y++)
	{
		for(x = x0; x < x1; x++)
		{
			double sum = 0, cov = 0;
			
			/* Supersample vertically too */
			for(j = 0; j < 4; j++)
			{
				double r = _row(tc, y) + (j - 1.5) / 4 * tc->rscale;
				double l = _wheel_luma((tc->t[x] - cx) / P, (r - cy) / 42, lx, ly);
				
				if(l >= 0)
				{
					sum += l;
					cov += 1;
				}
			}
			
			if(cov > 0)
			{
				_blend(tc, y * tc->sw + x, _grey(sum / cov), cov / 4);
			}
		}
	}
	
	/* Labels, centred on the arcs at 45 degrees */
	_glyph_c(tc, &tc_glyph_n20, cx + lx * 1.172 * M_SQRT1_2 * P, cy + ly * 1.172 * M_SQRT1_2 * 42, ART_169, 1.0, _grey(1.0));
	_glyph_c(tc, &tc_glyph_n35, cx - lx * 0.828 * M_SQRT1_2 * P, cy - ly * 0.828 * M_SQRT1_2 * 42, ART_169, 1.0, _grey(1.0));
}

/* Vertical frequency sweep: luma = 0.5 + 0.5 cos(2 pi (f0 x + c x^2)), x in lines from the top (or bottom) */
static void _ladder(tc_t *tc, double t0, double t1, double r0, double r1, int up)
{
	int x, y, x0, x1, y0, y1;
	
	_rows(tc, r0, r1, &y0, &y1);
	_cols(tc, t0, t1, &x0, &x1);
	
	for(y = y0; y < y1; y++)
	{
		double r = _row(tc, y);
		double d = up ? r1 - 0.5 - r : r - r0 - 0.5;
		double l = 0.5 + 0.5 * cos(2 * M_PI * (0.0652176 * d + 0.000472589 * d * d));
		
		for(x = x0; x < x1; x++)
		{
			_blend(tc, y * tc->sw + x, _grey(l), 1.0);
		}
	}
}

/* Diagonal grating: luma = 0.5 + 0.5 cos(2 pi (fh t + fv r) + phase) */
static void _diagonal(tc_t *tc, double t0, double t1, double r0, double r1, double fh, double fv, double phase)
{
	int x, y, x0, x1, y0, y1;
	
	_rows(tc, r0, r1, &y0, &y1);
	_cols(tc, t0, t1, &x0, &x1);
	
	for(y = y0; y < y1; y++)
	{
		double r = _row(tc, y);
		
		for(x = x0; x < x1; x++)
		{
			double t = tc->t[x - x % TC_SS] + (tc->t[1] - tc->t[0]) * (TC_SS - 1) / 2;
			_blend(tc, y * tc->sw + x, _grey(0.5 + 0.5 * cos(2 * M_PI * (fh * t + fv * r) + phase)), 1.0);
		}
	}
}

static void _pm5644(tc_t *tc)
{
	const philips_t ph = {
		.p = 2.13654,
		.lw = 0.2006,
		.edge = 11.5,
		.cast_odd = 0,
		.thin = -2.5 * 2.13654,
		.phase = { -2.8441, -0.2482, 0.6003, -0.2630, -2.8336 },
		.art = ART_169,
	};
	const double P = ph.p;
	const double w = ph.lw;
	int k, s;
	
	_philips(tc, &ph);
	
	/* Centre marks top and bottom */
	_rect(tc, -0.25 * P, 0.25 * P, 22, 24, _grey(1.0), TC_NOCLIP);
	_rect(tc, -0.25 * P, 0.25 * P, 28, 30, _grey(1.0), TC_NOCLIP);
	_rect(tc, -0.25 * P, 0.25 * P, 546, 548, _grey(1.0), TC_NOCLIP);
	_rect(tc, -0.25 * P, 0.25 * P, 552, 554, _grey(1.0), TC_NOCLIP);
	
	for(s = -1; s <= 1; s += 2)
	{
		/* Resolution wheels */
		_wheel(tc, P, s * 9.5 * P,  99, s, -1);
		_wheel(tc, P, s * 9.5 * P, 477, s,  1);
		
		/* Vertical frequency sweep, increasing downwards on the left and upwards on the right */
		_ladder(tc, s * 10 * P - (0.5 * P - w / 2), s * 10 * P + (0.5 * P - w / 2), 184, 392, s > 0);
		
		/* Three vertical lines */
		for(k = 0; k < 3; k++)
		{
			_vline(tc, s * (22.880 + k * 0.520), w, 275, 301, _grey(1.0), TC_NOCLIP);
		}
	}
	
	/* Diagonal gratings */
	_diagonal(tc, -9.5 * P + w / 2, -7.5 * P - w / 2, 184, 266, -3.62619,  0.18446, -2.2444);
	_diagonal(tc, -9.5 * P + w / 2, -7.5 * P - w / 2, 310, 392, -2.41746, -0.12298, -0.4255);
	_diagonal(tc,  7.5 * P + w / 2,  9.5 * P - w / 2, 184, 266, -3.62619, -0.18446, -0.8639);
	_diagonal(tc,  7.5 * P + w / 2,  9.5 * P - w / 2, 310, 392,  2.41746, -0.12298,  1.6468);
}

/*** FuBK ***/

/* Ring (circle outline) of half thickness hw, as a fraction of the radius */
static void _ring(tc_t *tc, double rt, double rr, double cr, double hw, yuv_t c)
{
	int x, y, x0, x1, y0, y1;
	
	_rows(tc, cr - rr * (1 + hw) - 2, cr + rr * (1 + hw) + 2, &y0, &y1);
	_cols(tc, -rt * (1 + hw) - 0.2, rt * (1 + hw) + 0.2, &x0, &x1);
	
	for(y = y0; y < y1; y++)
	{
		double b = (_row(tc, y) - cr) / rr;
		
		for(x = x0; x < x1; x++)
		{
			double a = tc->t[x] / rt;
			double d = fabs(sqrt(a * a + b * b) - 1.0);
			
			/* Soft edges, about one line wide */
			d = (hw - d) / (1.0 / rr) + 0.5;
			_blend(tc, y * tc->sw + x, c, d < 0 ? 0 : (d > 1 ? 1 : d));
		}
	}
}

/* Luma = colour difference ramp, flat at l0 up to t0 then falling to zero at t1 */
static void _ramp(tc_t *tc, double ta, double t0, double t1, double r0, double r1, double l0, int v)
{
	int x, y, x0, x1, y0, y1;
	
	_rows(tc, r0, r1, &y0, &y1);
	_cols(tc, ta, t1, &x0, &x1);
	
	for(y = y0; y < y1; y++)
	{
		for(x = x0; x < x1; x++)
		{
			double t = tc->t[x];
			double l = t < t0 ? l0 : l0 * (t1 - t) / (t1 - t0);
			_blend(tc, y * tc->sw + x, v ? _yuv(l, 0, l) : _yuv(l, l, 0), 1.0);
		}
	}
}

/* Grating that starts at a rising zero crossing at t0 */
static void _burst(tc_t *tc, double t0, double t1, double r0, double r1, double f)
{
	_grating(tc, t0, t1, r0, r1, f, -2 * M_PI * f * t0, 0.5, 0.5, TC_NOCLIP);
}

static void _fubk(tc_t *tc)
{
	const double P = 2.71278;
	const double w = 0.2;
	const double L = -6 * P + w / 2;
	const double R = 6 * P - w / 2;
	int k, x, y, x0, x1, y0, y1;
	double ru, rv, s;
	
	/* Background and grid */
	_rect(tc, -1e3, 1e3, -1e3, 1e3, _grey(0.25), TC_NOCLIP);
	
	for(k = -10; k <= 10; k++)
	{
		_vline(tc, k * P, w, -1e3, 1e3, _grey(1.0), TC_NOCLIP);
	}
	
	for(k = 0; k < 15; k++)
	{
		_rect(tc, -1e3, 1e3, 6 + k * 40, 8 + k * 40, _grey(1.0), TC_NOCLIP);
	}
	
	/* 75% colour bars */
	_rect(tc, L, -4.5 * P, 88, 207, _grey(0.75), TC_NOCLIP);
	_rect(tc, -4.5 * P, -3.0 * P, 88, 207, _rgb(0.75, 0.75, 0.00), TC_NOCLIP);
	_rect(tc, -3.0 * P, -1.5 * P, 88, 207, _rgb(0.00, 0.75, 0.75), TC_NOCLIP);
	_rect(tc, -1.5 * P,  0.0 * P, 88, 207, _rgb(0.00, 0.75, 0.00), TC_NOCLIP);
	_rect(tc,  0.0 * P,  1.5 * P, 88, 207, _rgb(0.75, 0.00, 0.75), TC_NOCLIP);
	_rect(tc,  1.5 * P,  3.0 * P, 88, 207, _rgb(0.75, 0.00, 0.00), TC_NOCLIP);
	_rect(tc,  3.0 * P,  4.5 * P, 88, 207, _rgb(0.00, 0.00, 0.75), TC_NOCLIP);
	_rect(tc,  4.5 * P, R, 88, 207, _grey(0.0), TC_NOCLIP);
	
	/* Grey scale */
	_rect(tc, L, -3.6 * P, 207, 286, _grey(0.00), TC_NOCLIP);
	_rect(tc, -3.6 * P, -1.2 * P, 207, 286, _grey(0.25), TC_NOCLIP);
	_rect(tc, -1.2 * P,  1.2 * P, 207, 286, _grey(0.50), TC_NOCLIP);
	_rect(tc,  1.2 * P,  3.6 * P, 207, 286, _grey(0.75), TC_NOCLIP);
	_rect(tc,  3.6 * P, R, 207, 286, _grey(1.00), TC_NOCLIP);
	
	/* Text box */
	_rect(tc, L, R, 286, 327, _grey(1.0), TC_NOCLIP);
	_rect(tc, -3.6 * P, 3.6 * P, 288, 327, _grey(0.0), TC_NOCLIP);
	
	/* Gratings, 1, 2, 3 and 4.43 MHz */
	_rect(tc, L, -12.3783, 327, 367, _grey(1.0), TC_NOCLIP);
	_rect(tc, -12.3783, R, 327, 367, _grey(0.5), TC_NOCLIP);
	_burst(tc, -11.6783, -6.6783, 327, 367, 1.0);
	_burst(tc,  -5.9782, -0.9782, 327, 367, 2.0);
	_burst(tc,   1.0217,  6.0217, 327, 367, 3.0);
	
	ru = -0.415;
	rv = 0.279;
	s = fmin(0.5 / (ru / -0.493), 1.0);   /* B >= 0 */
	_rect(tc, 6.7217, 14.7217, 327, 367, _yuv(0.5, ru * s, rv * s), TC_NOCLIP);
	
	/* Centre line */
	_vline(tc, 0, w, 207, 367, _grey(1.0), TC_NOCLIP);
	
	/* Triangle */
	_rect(tc, L, R, 367, 407, _grey(1.0), TC_NOCLIP);
	_rows(tc, 367, 407, &y0, &y1);
	
	for(y = y0; y < y1; y++)
	{
		double e = 0.5 - 0.8 / 39.0 * (_row(tc, y) - 367.5);
		_cols(tc, -0.5, e, &x0, &x1);
		for(x = x0; x < x1; x++) _blend(tc, y * tc->sw + x, _grey(0.0), 1.0);
	}
	
	/* ±V / +U ramps */
	_ramp(tc, L, -4 * P, 2 * P, 407, 448, 0.375, 1);
	_ramp(tc, L, -4 * P, 2 * P, 448, 486, 0.375, 0);
	_rect(tc, 2 * P, 2 * P + w / 2, 407, 486, _grey(0.0), TC_NOCLIP);
	
	/* Anti-PAL fields */
	_alt(tc, 2 * P + w / 2, 4 * P - w / 2, 407, 486, 0.375, 0.0, 0.375, TC_NOCLIP);
	_rect(tc, 4 * P - w / 2, 4 * P + w / 2, 407, 486, _grey(0.0), TC_NOCLIP);
	_alt(tc, 4 * P + w / 2, R, 407, 486, 0.375, -0.375, 0.0, TC_NOCLIP);
	
	/* Circle */
	_ring(tc, 18.18, 268, 287, 0.0055, _grey(1.0));
	
	/* HACK TV logo in the left half of the text box */
	_logo(tc, -3.6 * P, -w / 2, 288, 327, ART_43);
}

/*** UEIT ***/

#define UX(u) (((u) - 384.5) * ART_43)

static yuv_t _rgb8(int r, int g, int b)
{
	return _rgb(r / 255.0, g / 255.0, b / 255.0);
}

static void _urect(tc_t *tc, double x0, double x1, double y0, double y1, yuv_t c, int clip)
{
	_rect(tc, UX(x0), UX(x1), y0, y1, c, clip);
}

static void _ucircle(tc_t *tc, double cx, double cy, double rx, double ry)
{
	tc->c_ct = UX(cx);
	tc->c_rt = rx * ART_43;
	tc->c_cr = cy;
	tc->c_rr = ry;
	tc->c_soft = 2.0 / (rx + ry);
}

/* Background grid, restricted to a rectangle */
static void _ugrid(tc_t *tc, int x0, int x1, int y0, int y1, int clip)
{
	int k;
	
	_urect(tc, x0, x1, y0, y1, _rgb8(96, 96, 96), clip);
	
	for(k = 0; k < 25; k++)
	{
		int x = 23 + k * 30;
		if(x + 2 <= x0 || x >= x1) continue;
		_urect(tc, fmax(x, x0), fmin(x + 2, x1), y0, y1, _rgb8(191, 191, 191), clip);
	}
	
	for(k = 0; k < 19; k++)
	{
		int y = 17 + k * 30;
		if(y + 2 <= y0 || y >= y1) continue;
		_urect(tc, x0, x1, fmax(y, y0), fmin(y + 2, y1), _rgb8(191, 191, 191), clip);
	}
}

/* Grating starting at the left edge, as a pixel range */
static void _ugrating(tc_t *tc, int x0, int x1, int y0, int y1, double f)
{
	_grating(tc, UX(x0), UX(x1), y0, y1, f, -2 * M_PI * f * UX(x0), 96 / 255.0, 64 / 255.0, TC_NOCLIP);
}

static void _usmall(tc_t *tc, int cx, int cy, double r, int dir)
{
	int x0 = cx - 29;
	int x1 = cx + 31;
	
	_ucircle(tc, cx, cy, r, r);
	_urect(tc, cx - 70, cx + 70, cy - 70, cy + 70, _rgb8(191, 191, 191), TC_INSIDE);
	
	/* Window onto the background grid, and the gratings */
	_ugrid(tc, x0, x1, cy - 11, cy + 11, TC_NOCLIP);
	_ugrating(tc, x0, x1, cy - 31, cy - 11, dir > 0 ? 3.0 : 4.0);
	_ugrating(tc, x0, x1, cy + 11, cy + 29, dir > 0 ? 4.0 : 3.0);
	
	_glyph_c(tc, &tc_glyph_u3, UX(cx - 38), cy - 15 * dir, ART_43, 1.0, _grey(0.0));
	_glyph_c(tc, &tc_glyph_u4, UX(cx - 38), cy + 15 * dir, ART_43, 1.0, _grey(0.0));
}

/* HACKTV block lettering: x0, x1, y0, y1 */
static const short _ueit_letters[][4] = {
	{ 303, 306, 114, 120 }, { 303, 316, 120, 123 }, { 303, 306, 123, 133 }, { 313, 316, 114, 120 }, { 313, 316, 123, 133 },
	{ 331, 334, 117, 123 }, { 331, 344, 123, 127 }, { 331, 334, 127, 133 }, { 334, 341, 114, 117 }, { 341, 344, 117, 123 },
	{ 341, 344, 127, 133 }, { 363, 366, 117, 130 }, { 366, 373, 114, 117 }, { 366, 373, 130, 133 }, { 373, 376, 117, 120 },
	{ 373, 376, 127, 130 }, { 391, 394, 114, 120 }, { 391, 397, 120, 123 }, { 391, 394, 123, 133 }, { 397, 401, 117, 120 },
	{ 397, 401, 123, 127 }, { 401, 404, 114, 117 }, { 401, 404, 127, 133 }, { 421, 437, 114, 117 }, { 427, 431, 117, 133 },
	{ 452, 455, 114, 127 }, { 455, 458, 127, 130 }, { 458, 462, 130, 133 }, { 462, 465, 127, 130 }, { 465, 468, 114, 127 },
};

static void _ueitm(tc_t *tc)
{
	const yuv_t white = _grey(1.0);
	const yuv_t black = _grey(0.0);
	const yuv_t light = _rgb8(191, 191, 191);
	const yuv_t dark = _rgb8(96, 96, 96);
	int k, y, x;
	
	/* Borders */
	_urect(tc, -100, 900, -100, 700, white, TC_NOCLIP);
	
	for(k = 0; k < 13; k++)
	{
		x = 25 + k * 60;
		
		if(k < 12)
		{
			_urect(tc, x, x + 30, -100, 17, black, TC_NOCLIP);
			_urect(tc, x, x + 30, 7, 9, white, TC_NOCLIP);
		}
		
		_urect(tc, x, x + 30, 559, 700, black, TC_NOCLIP);
		_urect(tc, x, x + 30, 567, 569, white, TC_NOCLIP);
	}
	
	_urect(tc, -100, 23, 17, 19, black, TC_NOCLIP);
	
	for(k = 0; k < 9; k++)
	{
		y = 49 + k * 60;
		_urect(tc, -100, 23, y, y + 30, black, TC_NOCLIP);
		_urect(tc, 10, 12, y, y + 30, white, TC_NOCLIP);
	}
	
	for(k = 0; k < 9; k++)
	{
		y = 19 + k * 60;
		_urect(tc, 745, 900, y, y + 30, black, TC_NOCLIP);
		_urect(tc, 756, 758, y, y + 30, white, TC_NOCLIP);
	}
	
	_urect(tc, 756, 758, 559, 567, white, TC_NOCLIP);
	_urect(tc, 756, 758, 569, 700, white, TC_NOCLIP);
	
	/* Background grid */
	_ugrid(tc, 23, 745, 17, 559, TC_NOCLIP);
	
	/* Large circle, with windows onto the grid */
	_ucircle(tc, 384, 288, 239.0, 238.13);
	_urect(tc, 100, 700, 0, 576, light, TC_INSIDE);
	_ugrid(tc, 325, 443, 63, 93, TC_NOCLIP);
	_ugrid(tc, 235, 533, 109, 137, TC_NOCLIP);
	_ugrid(tc, 325, 443, 483, 513, TC_NOCLIP);
	for(k = 0; k < sizeof(_ueit_letters) / sizeof(_ueit_letters[0]); k++)
	{
		_urect(tc, _ueit_letters[k][0], _ueit_letters[k][1], _ueit_letters[k][2], _ueit_letters[k][3], light, TC_NOCLIP);
	}
	
	/* Desaturated colour bars */
	_urect(tc,  23, 115, 139, 197, _rgb8(191, 191, 191), TC_NOCLIP);
	_urect(tc, 115, 205, 139, 197, _rgb8(191, 191,  96), TC_NOCLIP);
	_urect(tc, 205, 295, 139, 197, _rgb8( 96, 191, 191), TC_NOCLIP);
	_urect(tc, 295, 385, 139, 197, _rgb8( 96, 191,  96), TC_NOCLIP);
	_urect(tc, 385, 475, 139, 197, _rgb8(191,  96, 191), TC_NOCLIP);
	_urect(tc, 475, 565, 139, 197, _rgb8(191,  96,  96), TC_NOCLIP);
	_urect(tc, 565, 655, 139, 197, _rgb8( 96,  96, 191), TC_NOCLIP);
	_urect(tc, 655, 745, 139, 197, _rgb8( 96,  96,  96), TC_NOCLIP);
	
	/* Grey scale */
	_urect(tc, 23, 113, 197, 229, black, TC_NOCLIP);
	
	for(k = 1; k <= 9; k++)
	{
		_urect(tc, 53 + k * 60, 113 + k * 60, 197, 229, _grey(k / 9.0), TC_NOCLIP);
	}
	
	_urect(tc, 653, 743, 197, 229, black, TC_NOCLIP);
	
	/* Colour stripes */
	_ucircle(tc, 384, 288, 239.0, 238.13);
	
	for(k = 0; k < 32; k++)
	{
		yuv_t c;
		
		if(k < 10) c = k & 1 ? _rgb8(191, 96, 191) : _rgb8(96, 191, 96);
		else if(k < 22) c = k & 1 ? _rgb8(191, 191, 96) : _rgb8(96, 96, 191);
		else c = k & 1 ? _rgb8(191, 96, 96) : _rgb8(96, 191, 191);
		
		_urect(tc, 143 + k * 15, 158 + k * 15, 229, 257, c, TC_INSIDE);
	}
	
	/* Centre: interlace and reflection checks */
	_urect(tc, 100, 295, 287, 317, black, TC_INSIDE);
	_urect(tc, 473, 700, 259, 289, black, TC_INSIDE);
	_urect(tc, 158, 160, 259, 287, black, TC_NOCLIP);
	_urect(tc, 158, 160, 289, 317, light, TC_NOCLIP);
	_urect(tc, 203, 205, 287, 289, light, TC_NOCLIP);
	_urect(tc, 263, 265, 287, 289, light, TC_NOCLIP);
	_urect(tc, 503, 505, 287, 289, light, TC_NOCLIP);
	_urect(tc, 563, 565, 287, 289, light, TC_NOCLIP);
	
	for(y = 0; y < 28; y++)
	{
		x = 602 - 4 * y;
		_urect(tc, x, x + 4, 259 + y, 260 + y, dark, TC_NOCLIP);
		_urect(tc, x + 1, x + 3, 259 + y, 260 + y, light, TC_NOCLIP);
		
		x = 276 - 4 * y;
		_urect(tc, x, x + 4, 289 + y, 290 + y, dark, TC_NOCLIP);
		_urect(tc, x + 1, x + 3, 289 + y, 290 + y, light, TC_NOCLIP);
	}
	
	_urect(tc, 295, 473, 259, 317, dark, TC_NOCLIP);
	_urect(tc, 353, 355, 259, 317, light, TC_NOCLIP);
	_urect(tc, 383, 385, 259, 317, light, TC_NOCLIP);
	_urect(tc, 413, 415, 259, 317, light, TC_NOCLIP);
	_urect(tc, 353, 415, 287, 289, light, TC_NOCLIP);
	_urect(tc, 323, 325, 287, 289, light, TC_NOCLIP);
	_urect(tc, 443, 445, 287, 289, light, TC_NOCLIP);
	
	/* Green to magenta ramp */
	{
		int x0, x1, y0, y1;
		yuv_t a = _rgb8(0, 216, 0);
		yuv_t b = _rgb(1.0, 38.9 / 255, 1.0);
		double ta = UX(145.5);
		double tb = UX(626.5);
		
		_rows(tc, 319, 347, &y0, &y1);
		_cols(tc, UX(100), UX(700), &x0, &x1);
		
		for(y = y0; y < y1; y++)
		{
			for(x = x0; x < x1; x++)
			{
				double f = (tc->t[x] - ta) / (tb - ta);
				yuv_t c = { a.y + (b.y - a.y) * f, a.u + (b.u - a.u) * f, a.v + (b.v - a.v) * f };
				_blend(tc, y * tc->sw + x, c, _circle_alpha(tc, tc->t[x], _row(tc, y)));
			}
		}
	}
	
	/* Gratings, 2, 3, 4 and 5 MHz */
	{
		const int box[7] = { 25, 145, 235, 325, 445, 535, 625 };
		const int end[7] = { 145, 235, 325, 445, 535, 625, 745 };
		const double f[7] = { 2, 3, 4, 5, 4, 3, 2 };
		const tc_glyph_t *g[7] = { &tc_glyph_g2, &tc_glyph_g3, &tc_glyph_g4, &tc_glyph_g5, &tc_glyph_g4, &tc_glyph_g3, &tc_glyph_g2 };
		
		_urect(tc, 25, 745, 347, 379, dark, TC_NOCLIP);
		
		for(k = 0; k < 7; k++)
		{
			_ugrating(tc, box[k] + 14, end[k], 347, 379, f[k]);
			_glyph_c(tc, g[k], UX(box[k] + 6), 363, ART_43, 1.0, light);
		}
	}
	
	/* Colour bars */
	_urect(tc,  23, 115, 379, 437, _rgb8(191, 191, 191), TC_NOCLIP);
	_urect(tc, 115, 205, 379, 437, _rgb8(191, 191,   0), TC_NOCLIP);
	_urect(tc, 205, 295, 379, 437, _rgb8(  0, 191, 191), TC_NOCLIP);
	_urect(tc, 295, 385, 379, 437, _rgb8(  0, 191,   0), TC_NOCLIP);
	_urect(tc, 385, 475, 379, 437, _rgb8(191,   0, 191), TC_NOCLIP);
	_urect(tc, 475, 565, 379, 437, _rgb8(191,   0,   0), TC_NOCLIP);
	_urect(tc, 565, 655, 379, 437, _rgb8(  0,   0, 191), TC_NOCLIP);
	_urect(tc, 655, 745, 379, 437, black, TC_NOCLIP);
	
	/* Black and white squares */
	_urect(tc, 23, 745, 437, 467, light, TC_NOCLIP);
	_urect(tc, 53, 173, 439, 467, black, TC_NOCLIP);
	_urect(tc, 203, 235, 439, 467, black, TC_NOCLIP);
	_urect(tc, 593, 713, 439, 467, black, TC_NOCLIP);
	_urect(tc, 200, 568, 439, 467, light, TC_INSIDE);
	
	for(k = 0; k < 6; k++)
	{
		_urect(tc, 235 + k * 60, 265 + k * 60, 439, 467, black, TC_INSIDE);
	}
	
	/* Small circles */
	_usmall(tc, 114, 78, 58.37, 1);
	_usmall(tc, 654, 78, 58.37, 1);
	_usmall(tc, 114, 498, 58.45, -1);
	_usmall(tc, 654, 498, 58.45, -1);
}

/*** Card table ***/

typedef struct {
	const char *name;
	const char *desc;
	double centre;          /* Card centre, µs from 0H in 625-line timing */
	float ratio;
	void (*render)(tc_t *tc);
} tc_card_t;

static const tc_card_t _cards[] = {
	{ "pm5544", "Philips PM5544 (4:3)",  36.518, 4.0 / 3.0, _pm5544 },
	{ "pm5644", "Philips PM5644 (16:9)", 36.5185, 16.0 / 9.0, _pm5644 },
	{ "fubk",   "FuBK (4:3)",            36.5185, 4.0 / 3.0, _fubk },
	{ "ueitm",  "UEIT (4:3)",            36.375, 4.0 / 3.0, _ueitm },
	{ NULL }
};

static const tc_card_t *_find(const char *name)
{
	const tc_card_t *c;

	for(c = _cards; c->name; c++)
	{
		if(strcmp(c->name, name) == 0) return(c);
	}

	return(NULL);
}

int testcard_exists(const char *name)
{
	return(_find(name) != NULL);
}

float testcard_ratio(const char *name)
{
	const tc_card_t *c = _find(name);
	return(c ? c->ratio : 4.0 / 3.0);
}

void testcard_list(void)
{
	const tc_card_t *c;

	for(c = _cards; c->name; c++)
	{
		fprintf(stderr, "\t-- %-8s %s\n", c->name, c->desc);
	}
}

int testcard_render_yuv(const char *name, const testcard_geometry_t *g, float *Y, float *U, float *V)
{
	const tc_card_t *card;
	tc_t tc;
	int x, y, i;
	double mid, scale;

	card = _find(name);
	if(!card) return(-1);

	memset(&tc, 0, sizeof(tc_t));
	tc.w = g->width;
	tc.h = g->height;
	tc.sw = g->width * TC_SS;
	tc.rscale = TC_REF_LINES / g->height;
	tc.logo = g->logo;

	tc.t = malloc(sizeof(double) * tc.sw);
	tc.Y = malloc(sizeof(float) * tc.sw * tc.h);
	tc.U = malloc(sizeof(float) * tc.sw * tc.h);
	tc.V = malloc(sizeof(float) * tc.sw * tc.h);

	if(!tc.t || !tc.Y || !tc.U || !tc.V)
	{
		free(tc.t);
		free(tc.Y);
		free(tc.U);
		free(tc.V);
		return(-1);
	}

	mid = (g->active_left + g->active_width / 2) * 1e6;
	scale = TC_REF_ACTIVE_WIDTH / (g->active_width * 1e6);

	for(x = 0; x < tc.sw; x++)
	{
		double t = g->pixel_left * 1e6 + ((x + 0.5) / TC_SS - 0.5) / g->pixel_rate * 1e6;
		tc.t[x] = (t - mid) * scale + (TC_REF_ACTIVE_LEFT + TC_REF_ACTIVE_WIDTH / 2) - card->centre;
	}

	card->render(&tc);

	/* Downsample */
	for(y = 0; y < tc.h; y++)
	{
		for(x = 0; x < tc.w; x++)
		{
			float sy = 0, su = 0, sv = 0;

			for(i = 0; i < TC_SS; i++)
			{
				int o = y * tc.sw + x * TC_SS + i;
				sy += tc.Y[o];
				su += tc.U[o];
				sv += tc.V[o];
			}

			Y[y * tc.w + x] = sy / TC_SS;
			U[y * tc.w + x] = su / TC_SS;
			V[y * tc.w + x] = sv / TC_SS;
		}
	}

	free(tc.t);
	free(tc.Y);
	free(tc.U);
	free(tc.V);

	return(0);
}

static int _clamp8(double v)
{
	v = round(v * 255.0);
	return(v < 0 ? 0 : (v > 255 ? 255 : (int) v));
}

int testcard_render(const char *name, const testcard_geometry_t *g, uint32_t *fb)
{
	float *Y, *U, *V;
	int i, n = g->width * g->height;

	Y = malloc(sizeof(float) * n * 3);
	if(!Y) return(-1);
	U = Y + n;
	V = U + n;

	if(testcard_render_yuv(name, g, Y, U, V) != 0)
	{
		free(Y);
		return(-1);
	}

	for(i = 0; i < n; i++)
	{
		double r = Y[i] + V[i] / 0.877;
		double b = Y[i] + U[i] / 0.493;
		double gg = (Y[i] - 0.299 * r - 0.114 * b) / 0.587;

		fb[i] = _clamp8(r) << 16 | _clamp8(gg) << 8 | _clamp8(b);
	}

	free(Y);

	return(0);
}
