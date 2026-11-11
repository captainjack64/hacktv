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

#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "hacktv.h"
#include "graphics.h"
#include "testcard.h"

/* AV test pattern source */
typedef struct {
	int width;
	int height;
	uint32_t *video;
	int16_t *audio;
	size_t audio_samples;
	image_t *logo;
	av_font_t *font[2];
} av_test_t;

static int _test_read_video(void *ctx, av_frame_t *frame)
{
	av_test_t *s = ctx;
	av_frame_init(frame, s->width, s->height, s->video, 1, s->width);
	av_set_display_aspect_ratio(frame, (r64_t) { 4, 3 });

	/* Print clock */
	if(s->font[TEXT_TIMESTAMP])
	{
		/* Get current time */
		time_t secs = time(0);
		struct tm *time = localtime(&secs);
		s->font[TEXT_TIMESTAMP]->text = malloc(16 * sizeof(char));
		sprintf(s->font[TEXT_TIMESTAMP]->text, "%02d:%02d:%02d", time->tm_hour, time->tm_min, time->tm_sec);

		print_generic_text(	s->font[TEXT_TIMESTAMP],
							s->video,
							s->width,
							s->font[TEXT_TIMESTAMP]->text,
							s->font[TEXT_TIMESTAMP]->x_loc, s->font[TEXT_TIMESTAMP]->y_loc, NO_TEXT_SHADOW, TEXT_BOX, 0, 1);

		/* Free memory */
		free(s->font[TEXT_TIMESTAMP]->text);
	}

	return(AV_OK);
}

static int _test_read_audio(void *ctx, int16_t **samples, size_t *nsamples)
{
	av_test_t *s = ctx;
	*samples = s->audio;
	*nsamples = s->audio_samples;
	return(AV_OK);
}

static int _test_close(void *ctx)
{
	av_test_t *s = ctx;
	if(s->video) free(s->video);
	if(s->audio) free(s->audio);
	free(s);
	return(AV_OK);
}

static float _clock_y(av_font_t *font, int height, double r0, double r1)
{
	FT_Face face = font->fontface;
	const char *d = "0123456789";
	double top, bottom, baseline;
	int h = 0;
	
	for(; *d; d++)
	{
		if(FT_Load_Char(face, *d, FT_LOAD_DEFAULT) == 0)
		{
			int gh = face->glyph->metrics.height >> 6;
			if(gh > h) h = gh;
		}
	}
	
	top = r0 * height / 576.0;
	bottom = r1 * height / 576.0;
	
	if(h * 1.425 <= bottom - top)
	{
		/* Box fits: align it with the bottom of the text box */
		baseline = bottom - h * 0.275;
	}
	else
	{
		/* Box too tall: centre the digits */
		baseline = (top + bottom) / 2 + h / 2.0;
	}
	
	/* print_generic_text() truncates the position */
	return((floor(baseline) + 0.5) * 100.0 / height);
}

int av_test_open(vid_t *vid, char *test_screen)
{
	uint32_t const bars[8] = {
		0x000000,
		0x0000BF,
		0xBF0000,
		0xBF00BF,
		0x00BF00,
		0x00BFBF,
		0xBFBF00,
		0xFFFFFF,
	};
	
	av_t *av = &vid->av;
	vid_config_t *conf = &vid->conf;
	av_test_t *t;
	int c, x, y;
	double d;
	int16_t l;
	
	t = calloc(1, sizeof(av_test_t));
	if(!t)
	{
		return(AV_OUT_OF_MEMORY);
	}
	
	/* Generate a basic test pattern */
	t->width = av->width;
	t->height = av->height;
	t->video = malloc(t->width * t->height * sizeof(uint32_t));
	
	if(!t->video)
	{
		free(t);
		return(AV_OUT_OF_MEMORY);
	}
	
	for(y = 0; y < t->height; y++)
	{
		for(x = 0; x < t->width; x++)
		{
			if(y < t->height - 140)
			{
				/* 75% colour bars */
				c = 7 - x * 8 / t->width;
				c = bars[c];
			}
			else if(y < t->height - 120)
			{
				/* 75% red */
				c = 0xBF0000;
			}
			else if(y < t->height - 100)
			{
				/* Gradient black to white */
				c = x * 0xFF / (t->width - 1);
				c = c << 16 | c << 8 | c;
			}
			else
			{
				/* 8 level grey bars */
				c = x * 0xFF / (t->width - 1);
				c &= 0xE0;
				c = c | (c >> 3) | (c >> 6);
				c = c << 16 | c << 8 | c;
			}
			
			t->video[y * t->width + x] = c;
		}
	}
	
	if(test_screen == NULL) test_screen = "pm5544";
	
	float img_ratio = testcard_exists(test_screen) ? testcard_ratio(test_screen) : 4.0 / 3.0;
	
	/* Initialise default fonts */
	
	/* Clock */
	font_init(av, 56 * t->height / 576, img_ratio, conf);
	t->font[TEXT_TIMESTAMP] = av->av_font;
	t->font[TEXT_TIMESTAMP]->x_loc = 50;
	t->font[TEXT_TIMESTAMP]->y_loc = 50;
	
	/* HACKTV text*/
	font_init(av, 72, img_ratio, conf);
	t->font[TEXT_GENERIC] = av->av_font;
	t->font[TEXT_GENERIC]->x_loc = 50;
	t->font[TEXT_GENERIC]->y_loc = 25;
	
	if(strcmp(test_screen, "colourbars") != 0 && !testcard_exists(test_screen))
	{
		fprintf(stderr, "\n%s: Unrecognised test pattern name.\n", test_screen);
		fprintf(stderr, "\nValid values are:\n");
		fprintf(stderr, "\t-- %-8s Colour bars\n", "colourbars");
		testcard_list();
	}
	
	if(testcard_exists(test_screen))
	{
		testcard_image_t logo = { NULL, 0, 0 };
		uint32_t *logo_data = NULL;
		
		if(load_png_rgba("hacktv", &logo_data, &logo.width, &logo.height) == HACKTV_OK)
		{
			logo.data = logo_data;
		}
		
		testcard_geometry_t g = {
			.width = t->width,
			.height = t->height,
			.pixel_rate = vid->pixel_rate,
			.pixel_left = (double) vid->active_left / vid->pixel_rate,
			.active_left = conf->active_left,
			.active_width = conf->active_width,
			.logo = logo.data ? &logo : NULL,
		};
		
		c = testcard_render(test_screen, &g, t->video);
		free(logo_data);
		
		if(c != 0)
		{
			free(t->video);
			free(t);
			return(AV_OUT_OF_MEMORY);
		}
		
		/* Position the clock in the card's text box */
		if(strcmp(test_screen, "pm5544") == 0 || strcmp(test_screen, "pm5644") == 0)
		{
			t->font[TEXT_TIMESTAMP]->y_loc = _clock_y(t->font[TEXT_TIMESTAMP], t->height, 434, 476);
		}
		else if(strcmp(test_screen, "fubk") == 0)
		{
			/* Reinit font with new size */
			font_init(av, 44 * t->height / 576, img_ratio, conf);
			t->font[TEXT_TIMESTAMP] = av->av_font;
			t->font[TEXT_TIMESTAMP]->x_loc = 52;
			t->font[TEXT_TIMESTAMP]->y_loc = _clock_y(t->font[TEXT_TIMESTAMP], t->height, 288, 327);
		}
		else if(strcmp(test_screen, "ueitm") == 0)
		{
			/* Don't display clock */
			t->font[TEXT_TIMESTAMP] = NULL;
		}
	}
	else
	{
		print_generic_text(	t->font[TEXT_GENERIC], t->video, t->width, "HACKTV", t->font[TEXT_GENERIC]->x_loc, t->font[TEXT_GENERIC]->y_loc, NO_TEXT_SHADOW, TEXT_BOX, 0, 1);
	}
	
	/* Print logo, if enabled */
	if(conf->logo)
	{
		if(load_png(&t->logo, t->width, t->height, conf->logo, 0.75, img_ratio, IMG_LOGO) == HACKTV_OK)
		{
			overlay_image(t->video, t->logo, t->width, t->width, t->height, t->logo->position);
		}
		else
		{
			conf->logo = NULL;
		}
	}
	
	/* Generate the 1khz test tones (BBC 1 style) */
	d = 1000.0 * 2 * M_PI * av->sample_rate.den / av->sample_rate.num;
	y = av->sample_rate.num / av->sample_rate.den * 64 / 100; /* 640ms */
	t->audio_samples = y * 10; /* 6.4 seconds */
	t->audio = malloc(t->audio_samples * 2 * sizeof(int16_t));
	if(!t->audio)
	{
		free(t->video);
		free(t);
		return(AV_OUT_OF_MEMORY);
	}
	
	for(x = 0; x < t->audio_samples; x++)
	{
		l = sin(x * d) * INT16_MAX * 0.1;
		
		if(x < y)
		{
			/* 0 - 640ms, interrupt left channel */
			t->audio[x * 2 + 0] = 0;
			t->audio[x * 2 + 1] = l;
		}
		else if(x >= y * 2 && x < y * 3)
		{
			/* 1280ms - 1920ms, interrupt right channel */
			t->audio[x * 2 + 0] = l;
			t->audio[x * 2 + 1] = 0;
		}
		else if(x >= y * 4 && x < y * 5)
		{
			/* 2560ms - 3200ms, interrupt right channel again */
			t->audio[x * 2 + 0] = l;
			t->audio[x * 2 + 1] = 0;
		}
		else
		{
			/* Use both channels for all other times */
			t->audio[x * 2 + 0] = l; /* Left */
			t->audio[x * 2 + 1] = l; /* Right */
		}
	}
	
	/* Register the callback functions */
	av->av_source_ctx = t;
	av->read_video = _test_read_video;
	av->read_audio = _test_read_audio;
	av->close = _test_close;
	
	return(AV_OK);
}

