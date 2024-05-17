/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2018 Philip Heron <phil@sanslogic.co.uk>                    */
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

/* Thread summary:
 * 
 * Input           - Reads the data from disk/network and feeds the
 *                   audio and/or video packet queues. Sets an EOF
 *                   flag on all queues when the input reaches the
 *                   end. Ends at EOF or abort.
 * 
 * Video decoder   - Reads from the video packet queue and produces
 *                   the decoded video frames.
 * 
 * Video scaler    - Rescales decoded video frames to the correct
 *                   size and format required by hacktv.
 * 
 * Audio thread    - Reads from the audio packet queue and produces
 *                   the decoded.
 *
 * Audio resampler - Resamples the decoded audio frames to the format
 *                   required by hacktv (32000Hz, Stereo, 16-bit)
*/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1

#define MAX(a,b) (((a) > (b)) ? (a) : (b))

#endif
#include <pthread.h>
#include <ctype.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavdevice/avdevice.h>
#include <libswscale/swscale.h>
#include <libswresample/swresample.h>
#include <libavutil/opt.h>
#include <libavutil/time.h>
#include <libavutil/imgutils.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/cpu.h>
#include "hacktv.h"
#include "keyboard.h"
#ifdef WIN32
#include <conio.h>
#endif

/* Maximum length of the packet queue */
/* Taken from ffplay.c */
#define MAX_QUEUE_SIZE (15 * 1024 * 1024)
#define AVSEEK_FWD 60
#define AVSEEK_RWD -60
#define AVSEEK_SEEKING 1

typedef struct __packet_queue_item_t {
	
	AVPacket pkt;
	struct __packet_queue_item_t *next;
	
} _packet_queue_item_t;

typedef struct {
	
	int length;	/* Number of packets */
	int size;       /* Number of bytes used */
	int eof;        /* End of stream / file flag */
	int abort;      /* Abort flag */
	
	/* Pointers to the first and last packets in the queue */
	_packet_queue_item_t *first;
	_packet_queue_item_t *last;
	
} _packet_queue_t;

typedef struct {
	
	int ready;	/* Frame ready flag */
	int repeat;	/* Repeat the previous frame */
	int abort;	/* Abort flag */
	
	/* The AVFrame buffers */
	AVFrame *frame[2];
	
	/* Thread locking and signaling */
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	
} _frame_dbuffer_t;

typedef struct {
	
	/* Seek stuff */
	int width;
	int height;
	int sample_rate;
	uint32_t *video;
	uint8_t paused;
	time_t last_paused;
	av_t *av;
	
	AVFormatContext *format_ctx;
	
	/* Video decoder */
	AVRational video_time_base;
	int64_t video_start_time;
	_packet_queue_t video_queue;
	AVStream *video_stream;
	AVCodecContext *video_codec_ctx;
	_frame_dbuffer_t in_video_buffer;
	int video_eof;
	
	/* Video scaling */
	struct SwsContext *sws_ctx;
	_frame_dbuffer_t out_video_buffer;
	
	/* Audio decoder */
	AVRational audio_time_base;
	int64_t audio_start_time;
	_packet_queue_t audio_queue;
	AVStream *audio_stream;
	AVCodecContext *audio_codec_ctx;
	_frame_dbuffer_t in_audio_buffer;
	int audio_eof;
	
	/* Audio resampler */
	struct SwrContext *swr_ctx;
	_frame_dbuffer_t out_audio_buffer;
	int out_frame_size;
	int allowed_error;
	
	/* Subtitle decoder */
	AVStream *subtitle_stream;
	AVCodecContext *subtitle_codec_ctx;
	int subtitle_eof;
	
	/* Threads */
	pthread_t input_thread;
	pthread_t video_decode_thread;
	pthread_t video_scaler_thread;
	pthread_t audio_decode_thread;
	pthread_t audio_scaler_thread;
	volatile int thread_abort;
	int input_stall;
	
	/* Thread locking and signaling for input queues */
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	
	/* Video filter buffers */
	AVFilterContext *vbuffersink_ctx;
	AVFilterContext *vbuffersrc_ctx;
	
	/* Audio filter buffers */
	AVFilterContext *abuffersink_ctx;
	AVFilterContext *abuffersrc_ctx;
	AVRational sar, dar;

	/* Callbacks */
	vid_config_t *vid_conf;
	tt_t *vid_tt;

	/* Subtitles */
	av_subs_t *av_sub;
	av_font_t *font[3];

	/* Video logo */
	image_t *av_logo;

	/* Media icons */
	image_t *media_icons[4];
} av_ffmpeg_t;

static void _print_ffmpeg_error(int r)
{
	char sb[128];
	const char *sp = sb;
	
	if(av_strerror(r, sb, sizeof(sb)) < 0)
	{
		sp = strerror(AVUNERROR(r));
	}
	
	fprintf(stderr, "%s\n", sp);
}

void _audio_offset(uint8_t const **dst, uint8_t const * const *src, int offset, int nb_channels, enum AVSampleFormat sample_fmt)
{
	int planar      = av_sample_fmt_is_planar(sample_fmt);
	int planes      = planar ? nb_channels : 1;
	int block_align = av_get_bytes_per_sample(sample_fmt) * (planar ? 1 : nb_channels);
	int i;
	
	offset *= block_align;
	
	for(i = 0; i < planes; i++)
	{
		dst[i] = src[i] + offset;
	}
}

static int _packet_queue_init(av_ffmpeg_t *s, _packet_queue_t *q)
{
	q->length = 0;
	q->size = 0;
	q->eof = 0;
	q->abort = 0;
	
	return(0);
}

static int _packet_queue_flush(av_ffmpeg_t *s, _packet_queue_t *q)
{
	_packet_queue_item_t *p;
	
	pthread_mutex_lock(&s->mutex);
	
	while(q->length--)
	{
		/* Pop the first item off the list */
		p = q->first;
		q->first = p->next;
		
		av_packet_unref(&p->pkt);
		free(p);
	}
	
	pthread_cond_signal(&s->cond);
	pthread_mutex_unlock(&s->mutex);
	
	return(0);
}

static void _packet_queue_free(av_ffmpeg_t *s, _packet_queue_t *q)
{
	_packet_queue_flush(s, q);
}

static void _packet_queue_abort(av_ffmpeg_t *s, _packet_queue_t *q)
{
	pthread_mutex_lock(&s->mutex);
	
	q->abort = 1;
	
	pthread_cond_signal(&s->cond);
	pthread_mutex_unlock(&s->mutex);
}

static int _packet_queue_write(av_ffmpeg_t *s, _packet_queue_t *q, AVPacket *pkt)
{
	_packet_queue_item_t *p;
	
	pthread_mutex_lock(&s->mutex);
	
	/* A NULL packet signals the end of the stream / file */
	if(pkt == NULL)
	{
		q->eof = 1;
	}
	else
	{
		/* Limit the size of the queue */
		while(q->abort == 0 && q->size + pkt->size + sizeof(_packet_queue_item_t) > MAX_QUEUE_SIZE)
		{
			s->input_stall = 1;
			pthread_cond_signal(&s->cond);
			pthread_cond_wait(&s->cond, &s->mutex);
		}
		
		s->input_stall = 0;
		
		if(q->abort == 1)
		{
			/* Abort was called while waiting for the queue size to drop */
			av_packet_unref(pkt);
			
			pthread_cond_signal(&s->cond);
			pthread_mutex_unlock(&s->mutex);
			
			return(-2);
		}
		
		/* Allocate memory for queue item and copy packet */
		p = malloc(sizeof(_packet_queue_item_t));
		p->pkt = *pkt;
		p->next = NULL;
		
		/* Add the item to the end of the queue */
		if(q->length == 0)
		{
			q->first = p;
		}
		else
		{
			q->last->next = p;
		}
		
		q->last = p;
		q->length++;
		q->size += pkt->size + sizeof(_packet_queue_item_t);
	}
	
	pthread_cond_signal(&s->cond);
	pthread_mutex_unlock(&s->mutex);
	
	return(0);
}

static int _packet_queue_read(av_ffmpeg_t *s, _packet_queue_t *q, AVPacket *pkt)
{
	_packet_queue_item_t *p;
	
	pthread_mutex_lock(&s->mutex);
	
	while(q->length == 0)
	{
		if(s->input_stall)
		{
			pthread_mutex_unlock(&s->mutex);
			return(0);
		}
		
		if(q->abort == 1 || q->eof == 1)
		{
			pthread_mutex_unlock(&s->mutex);
			return(q->abort == 1 ? -2 : -1);
		}
		
		pthread_cond_wait(&s->cond, &s->mutex);
	}
	
	p = q->first;
	
	*pkt = p->pkt;
	q->first = p->next;
	q->length--;
	q->size -= pkt->size + sizeof(_packet_queue_item_t);
	
	free(p);
	
	pthread_cond_signal(&s->cond);
	pthread_mutex_unlock(&s->mutex);
	
	return(0);
}

static int _frame_dbuffer_init(_frame_dbuffer_t *d)
{
	d->ready = 0;
	d->repeat = 0;
	d->abort = 0;
	
	d->frame[0] = av_frame_alloc();
	d->frame[1] = av_frame_alloc();
	
	if(!d->frame[0] || !d->frame[1])
	{
		av_frame_free(&d->frame[0]);
		av_frame_free(&d->frame[1]);
		return(-1);
	}
	
	pthread_mutex_init(&d->mutex, NULL);
	pthread_cond_init(&d->cond, NULL);
	
	return(0);
}

static void _frame_dbuffer_free(_frame_dbuffer_t *d)
{
	pthread_cond_destroy(&d->cond);
	pthread_mutex_destroy(&d->mutex);
	
	av_frame_free(&d->frame[0]);
	av_frame_free(&d->frame[1]);
}

static void _frame_dbuffer_abort(_frame_dbuffer_t *d)
{
	pthread_mutex_lock(&d->mutex);
	
	d->abort = 1;
	
	pthread_cond_signal(&d->cond);
	pthread_mutex_unlock(&d->mutex);
}

static AVFrame *_frame_dbuffer_back_buffer(_frame_dbuffer_t *d)
{
	AVFrame *frame;
	pthread_mutex_lock(&d->mutex);
	
	/* Wait for the ready flag to be unset */
	while(d->ready != 0 && d->abort == 0)
	{
		pthread_cond_wait(&d->cond, &d->mutex);
	}
	
	frame = d->frame[1];
	
	pthread_mutex_unlock(&d->mutex);
	
	return(frame);
}

static void _frame_dbuffer_ready(_frame_dbuffer_t *d, int repeat)
{
	pthread_mutex_lock(&d->mutex);
	
	/* Wait for the ready flag to be unset */
	while(d->ready != 0 && d->abort == 0)
	{
		pthread_cond_wait(&d->cond, &d->mutex);
	}
	
	d->ready = 1;
	d->repeat = repeat;
	
	pthread_cond_signal(&d->cond);
	pthread_mutex_unlock(&d->mutex);
}

static AVFrame *_frame_dbuffer_flip(_frame_dbuffer_t *d)
{
	AVFrame *frame;
	
	pthread_mutex_lock(&d->mutex);
	
	/* Wait for a flag to be set */
	while(d->ready == 0 && d->abort == 0)
	{
		pthread_cond_wait(&d->cond, &d->mutex);
	}
	
	/* Die if it was the abort flag */
	if(d->abort != 0)
	{
		pthread_mutex_unlock(&d->mutex);
		return(NULL);
	}
	
	/* Swap the frames if we're not repeating */
	if(d->repeat == 0)
	{
		frame       = d->frame[1];
		d->frame[1] = d->frame[0];
		d->frame[0] = frame;
	}
	
	frame = d->frame[0];
	d->ready = 0;
	
	/* Signal we're finished and release the mutex */
	pthread_cond_signal(&d->cond);
	pthread_mutex_unlock(&d->mutex);
	
	return(frame);
}

static void *_input_thread(void *arg)
{
	av_ffmpeg_t *s = (av_ffmpeg_t *) arg;
	AVPacket pkt;
	int r;
	
	//fprintf(stderr, "_input_thread(): Starting\n");
	
	/* Fetch packets from the source */
	while(s->thread_abort == 0)
	{
		r = av_read_frame(s->format_ctx, &pkt);
		
		if(r == AVERROR(EAGAIN))
		{
			av_usleep(10000);
			continue;
		}
		else if(r < 0)
		{
			/* FFmpeg input EOF or error. Break out */
			break;
		}
		
		if(s->video_stream && pkt.stream_index == s->video_stream->index)
		{
			_packet_queue_write(s, &s->video_queue, &pkt);
		}
		else if(s->audio_stream && pkt.stream_index == s->audio_stream->index)
		{
			_packet_queue_write(s, &s->audio_queue, &pkt);
		}
		/* Keep it in the input thread rather than moving to a separate one */
		else if(s->subtitle_stream && pkt.stream_index == s->subtitle_stream->index && s->av_sub)
		{
			AVSubtitle sub;
			int got_frame;
			
			r = avcodec_decode_subtitle2(s->subtitle_codec_ctx, &sub, &got_frame, &pkt);
			
			if(got_frame)
			{
				int i;
				
				if(sub.format == SUB_TEXT)
				{
					/* Load text subtitle into buffer */
					load_text_subtitle(s->av_sub, pkt.pts + sub.start_display_time, sub.end_display_time, sub.rects[0]->ass);
				}
				else if(sub.format == SUB_BITMAP)
				{
					int bitmap_width, max_bitmap_width, max_bitmap_height;
					float bitmap_ratio, bitmap_scale;

					max_bitmap_width = 0;
					max_bitmap_height = 0;
					
					for(i = 0; i < sub.num_rects; i++)
					{
						/* Scale bitmap to video width */
						bitmap_scale = sub.rects[i]->w / s->width < 1 ? 1 : round(sub.rects[i]->w / s->width);
						
						/* Get maximum width */
						max_bitmap_width = MAX(max_bitmap_width, sub.rects[i]->w / bitmap_scale);
						
						/* Get total height of all rects */
						max_bitmap_height += sub.rects[i]->h / bitmap_scale;
					}

					/* Set correct ratio based on supplied parameters */
					bitmap_ratio = s->vid_conf->pillarbox || s->vid_conf->letterbox ? 4.0/3.0 : 16.0/9.0;
					bitmap_width = (float) (s->width / (float) s->height) / bitmap_ratio * max_bitmap_width;
					load_bitmap_subtitle(&sub, s->av_sub, bitmap_width, max_bitmap_width, max_bitmap_height, pkt.pts, bitmap_scale);
				}
				
				avsubtitle_free(&sub);
			}
			else if(r != AVERROR(EAGAIN))
			{
				/* avcodec_receive_frame returned an EOF or error, abort thread */
				//break;
			}
			
			av_packet_unref(&pkt);
		}
		else
		{
			av_packet_unref(&pkt);
		}
	}
	
	/* Set the EOF flag in the queues */
	_packet_queue_write(s, &s->video_queue, NULL);
	_packet_queue_write(s, &s->audio_queue, NULL);
	
	//fprintf(stderr, "_input_thread(): Ending\n");
	
	return(NULL);
}

static void *_video_decode_thread(void *arg)
{
	av_ffmpeg_t *s = (av_ffmpeg_t *) arg;
	AVPacket pkt, *ppkt = NULL;
	AVFrame *frame;
	int r;
	
	//fprintf(stderr, "_video_decode_thread(): Starting\n");
	
	frame = av_frame_alloc();
	
	/* Fetch video packets from the queue and decode */
	while(s->thread_abort == 0)
	{
		if(ppkt == NULL)
		{
			r = _packet_queue_read(s, &s->video_queue, &pkt);
			if(r == -2)
			{
				/* Thread is aborting */
				break;
			}
			
			ppkt = (r >= 0 ? &pkt : NULL);
		}
		
		r = avcodec_send_packet(s->video_codec_ctx, ppkt);
		
		if(ppkt != NULL && r != AVERROR(EAGAIN))
		{
			av_packet_unref(ppkt);
			ppkt = NULL;
		}
		
		if(r < 0 && r != AVERROR(EAGAIN))
		{
			/* avcodec_send_packet() has failed, abort thread */
			break;
		}
		
		r = avcodec_receive_frame(s->video_codec_ctx, frame);
		
		if(r == 0)
		{
			/* Push the decoded frame into the filtergraph */
			if (av_buffersrc_add_frame(s->vbuffersrc_ctx, frame) < 0) 
			{
				printf( "Error while feeding the video filtergraph\n");
			}

			/* Pull filtered frame from the filtergraph */ 
			if(av_buffersink_get_frame(s->vbuffersink_ctx, frame) < 0) 
			{
				printf( "Error while sourcing the video filtergraph\n");
			}
			
			/* We have received a frame! */
			av_frame_ref(_frame_dbuffer_back_buffer(&s->in_video_buffer), frame);
			_frame_dbuffer_ready(&s->in_video_buffer, 0);
		}
		else if(r != AVERROR(EAGAIN))
		{
			/* avcodec_receive_frame returned an EOF or error, abort thread */
			break;
		}
	}
	
	_frame_dbuffer_abort(&s->in_video_buffer);
	
	av_frame_free(&frame);
	
	//fprintf(stderr, "_video_decode_thread(): Ending\n");
	
	return(NULL);
}

static void *_video_scaler_thread(void *arg)
{
	av_ffmpeg_t *s = (av_ffmpeg_t *) arg;
	AVFrame *frame, *oframe;
	AVRational ratio;
	rational_t r;
	int64_t pts;
	
	/* Fetch video frames and pass them through the scaler */
	while((frame = _frame_dbuffer_flip(&s->in_video_buffer)) != NULL)
	{
		pts = frame->best_effort_timestamp;
		
		if(pts != AV_NOPTS_VALUE)
		{
			pts  = av_rescale_q(pts, s->video_stream->time_base, s->video_time_base);
			pts -= s->video_start_time;
			
			if(pts < 0)
			{
				/* This frame is in the past. Skip it */
				av_frame_unref(frame);
				continue;
			}
			
			while(pts > 0)
			{
				/* This frame is in the future. Repeat the previous one */
				_frame_dbuffer_ready(&s->out_video_buffer, 1);
				s->video_start_time++;
				pts--;
			}
		}
		
		oframe = _frame_dbuffer_back_buffer(&s->out_video_buffer);
		
		ratio = av_guess_sample_aspect_ratio(s->format_ctx, s->video_stream, frame);
		
		if(ratio.num == 0 || ratio.den == 0)
		{
			/* Default to square pixels if the ratio looks odd */
			ratio = (AVRational) { 1, 1 };
		}
		
		r = av_calculate_frame_size(
			s->av,
			(rational_t) { frame->width, frame->height },
			rational_mul(
				(rational_t) { ratio.num, ratio.den },
				(rational_t) { frame->width, frame->height }
			)
		);
		
		if(r.num != oframe->width ||
		   r.den != oframe->height)
		{
			av_freep(&oframe->data[0]);
			
			oframe->format = AV_PIX_FMT_RGB32;
			oframe->width = r.num;
			oframe->height = r.den;
			
			int i = av_image_alloc(
				oframe->data,
				oframe->linesize,
				oframe->width, oframe->height,
				AV_PIX_FMT_RGB32, av_cpu_max_align()
			);
			memset(oframe->data[0], 0, i);
		}
		
		/* Initialise / re-initialise software scaler */
		s->sws_ctx = sws_getCachedContext(
			s->sws_ctx,
			frame->width,
			frame->height,
			frame->format,
			oframe->width,
			oframe->height,
			AV_PIX_FMT_RGB32,
			SWS_BICUBIC,
			NULL,
			NULL,
			NULL
		);
		
		if(!s->sws_ctx) break;
		
		sws_scale(
			s->sws_ctx,
			(uint8_t const * const *) frame->data,
			frame->linesize,
			0,
			s->video_codec_ctx->height,
			oframe->data,
			oframe->linesize
		);
		
		/* Adjust the pixel ratio for the scaled image */
		av_reduce(
			&oframe->sample_aspect_ratio.num,
			&oframe->sample_aspect_ratio.den,
			frame->width * ratio.num * oframe->height,
			frame->height * ratio.den * oframe->width,
			INT_MAX
		);

		/* I don't like these routines here but it doesn't do any harm (I think) */
		/* Print timestamp of the video to console */
		int sec, hr, min, pts;
		pts = (frame->best_effort_timestamp / (s->video_stream->time_base.den / s->video_stream->time_base.num));
		hr  = (pts / 3600);
		min = (pts - (3600 * hr)) / 60;
		sec = (pts - (3600 * hr) - (min * 60));

		fprintf(stderr,"\r%02d:%02d:%02d", hr, min, sec);

		/* Overlay timestamp to video frame, if enabled */
		if(s->font[TEXT_TIMESTAMP])
		{
			asprintf(&s->font[TEXT_TIMESTAMP]->text, "%02d:%02d:%02d", hr, min, sec);
			print_generic_text(s->font[TEXT_TIMESTAMP], (uint32_t *) oframe->data[0], s->font[TEXT_TIMESTAMP]->text, 10, 90, TEXT_SHADOW, NO_TEXT_BOX, 0, 0);

			/* Free memory */
			free(s->font[TEXT_TIMESTAMP]->text);
		}

		/* Print logo, if enabled */
		if(s->av_logo)
		{
			overlay_image((uint32_t *) oframe->data[0], s->av_logo, oframe->width + 2, oframe->height, s->av_logo->position);
		}
	
		/* Print subtitles to video frame, if enabled */
		if(s->font[TEXT_SUBTITLE])
		{
			if(get_subtitle_type(s->av_sub) == SUB_TEXT)
			{
				/* best_effort_timestamp is very flaky - not really a good measure of current position and doesn't work some of the time */
				asprintf(&s->font[TEXT_SUBTITLE]->text,"%s", get_text_subtitle(s->av_sub, frame->best_effort_timestamp / (s->video_stream->time_base.den / 1000)));

				/* Do not refresh teletext unless subtitle text has changed */
				if(s->vid_conf->txsubtitles && strcmp(s->font[TEXT_SUBTITLE]->text, s->vid_tt->text) != 0)
				{
					strcpy(s->vid_tt->text, s->font[TEXT_SUBTITLE]->text);
					update_teletext_subtitle(s->vid_tt->text, &s->vid_tt->service);
				}

				if(s->vid_conf->subtitles)
				{
					print_subtitle(s->font[TEXT_SUBTITLE], (uint32_t *) oframe->data[0], s->font[TEXT_SUBTITLE]->text);
				}

				/* Free memory */
				free(s->font[TEXT_SUBTITLE]->text);
			}
			else
			{
				int w, h, sindex;
				sindex = get_bitmap_subtitle(s->av_sub, frame->best_effort_timestamp, &w, &h);				
				if(w > 0) display_bitmap_subtitle(s->font[TEXT_SUBTITLE], (uint32_t *) oframe->data[0], w, h, s->av_sub[sindex].bitmap);
			}
		}

		/* Copy some data to the scaled image */
#if LIBAVUTIL_VERSION_INT >= AV_VERSION_INT(58, 29, 100)
		oframe->interlaced_frame = frame->flags & AV_FRAME_FLAG_INTERLACED ? 1 : 0;
		oframe->top_field_first = frame->flags & AV_FRAME_FLAG_TOP_FIELD_FIRST ? 1 : 0;
#else
		oframe->interlaced_frame = frame->interlaced_frame;
		oframe->top_field_first = frame->top_field_first;
#endif
		
		/* Done with the frame */
		av_frame_unref(frame);
		
		_frame_dbuffer_ready(&s->out_video_buffer, 0);
		s->video_start_time++;
	}
	
	_frame_dbuffer_abort(&s->out_video_buffer);
	
	// fprintf(stderr, "_video_scaler_thread(): Ending\n");
	
	return(NULL);
}

static int _ffmpeg_read_video(void *ctx, av_frame_t *frame)
{
	av_ffmpeg_t *s = ctx;
	AVFrame *avframe;
		
	// int nav;
	// nav = 0;

	av_frame_init(frame, 0, 0, NULL, 0, 0);

	if(s->video_stream == NULL)
	{
		return(AV_OK);
	}

	kb_enable();
	if(kbhit())
	{
		#ifndef WIN32
		char c = getchar();
		#else
		char c = getch();
		#endif
		switch(c)
		{
			case ' ':
				s->paused ^= 1;
				fprintf(stderr,"\nVideo state: %s", s->paused ? "PAUSE" : "PLAY");	
				break;
/*			case '\033':
				#ifndef WIN32
				getchar();
				c = getchar();
				#else
				c = getch();
				#endif
				switch(c)
				{
					case 'C':
						fprintf(stderr,"\nVideo state: FF");
						nav = AVSEEK_FWD;
						break;
					case 'D':
						fprintf(stderr,"\nVideo state: RW");
						nav = AVSEEK_RWD;
						break;
					default:
						break;
				}
				break;
*/
			default: 
				break;
		}
	}
	kb_disable();

/*
	if(nav == AVSEEK_FWD || nav == AVSEEK_RWD)
	{
		s->video_start_time += nav;
		s->audio_start_time += nav;
		nav = 0;
	}
*/	
	if(s->paused) 
	{
		avframe = s->out_video_buffer.frame[0];
		
		overlay_image((uint32_t *) avframe->data[0], s->media_icons[1], avframe->width + 2, avframe->height, IMG_POS_MIDDLE);
		s->last_paused = time(0);
	}
	else
	{
		avframe = _frame_dbuffer_flip(&s->out_video_buffer);
		/* Show 'play' icon for 5 seconds after resuming play */
		if(time(0) - s->last_paused < 5)
		{
			overlay_image((uint32_t *) avframe->data[0], s->media_icons[0], avframe->width + 2, avframe->height, IMG_POS_MIDDLE);
		}
	}

	if(!avframe)
	{
		/* EOF or abort */
		s->video_eof = 1;
		return(AV_OK);
	}
	
	/* Return image ratio */
	if(avframe->sample_aspect_ratio.num > 0 &&
	   avframe->sample_aspect_ratio.den > 0)
	{
		frame->pixel_aspect_ratio = (rational_t) {
			avframe->sample_aspect_ratio.num,
			avframe->sample_aspect_ratio.den
		};
	}
	
	/* Return interlace status */
	if(avframe->interlaced_frame)
	{
		frame->interlaced = avframe->top_field_first ? 1 : 2;
	}
	
	/* Set the pointer to the framebuffer */
	frame->width = avframe->width;
	frame->height = avframe->height;
	frame->framebuffer = (uint32_t *) avframe->data[0];
	frame->pixel_stride = 1;
	frame->line_stride = avframe->linesize[0] / sizeof(uint32_t);

	return(AV_OK);
}

static void *_audio_decode_thread(void *arg)
{
	/* TODO: This function is virtually identical to _video_decode_thread(),
	 *       they should probably be combined */
	av_ffmpeg_t *s = (av_ffmpeg_t *) arg;
	AVPacket pkt, *ppkt = NULL;
	AVFrame *frame;
	int r;
	
	//fprintf(stderr, "_audio_decode_thread(): Starting\n");
	
	frame = av_frame_alloc();
	
	/* Fetch audio packets from the queue and decode */
	while(s->thread_abort == 0)
	{
		if(ppkt == NULL)
		{
			r = _packet_queue_read(s, &s->audio_queue, &pkt);
			if(r == -2)
			{
				/* Thread is aborting */
				break;
			}
			
			ppkt = (r >= 0 ? &pkt : NULL);
		}
		
		r = avcodec_send_packet(s->audio_codec_ctx, ppkt);
		
		if(ppkt != NULL && r != AVERROR(EAGAIN))
		{
			av_packet_unref(ppkt);
			ppkt = NULL;
		}
		
		r = avcodec_receive_frame(s->audio_codec_ctx, frame);
		
		if(r == 0)
		{
			/* Push the decoded frame into the filtergraph */
			if (av_buffersrc_add_frame(s->abuffersrc_ctx, frame) < 0) 
			{
				fprintf(stderr, "Error while feeding the audio filtergraph\n");
			}

			/* Pull filtered frame from the filtergraph */ 
			if(av_buffersink_get_frame(s->abuffersink_ctx, frame) < 0) 
			{
				fprintf(stderr, "Error while sourcing the audio filtergraph\n");
			}
			
			/* We have received a frame! */
			av_frame_ref(_frame_dbuffer_back_buffer(&s->in_audio_buffer), frame);
			_frame_dbuffer_ready(&s->in_audio_buffer, 0);
		}
		else if(r != AVERROR(EAGAIN))
		{
			/* avcodec_receive_frame returned an EOF or error, abort thread */
			break;
		}
	}
	
	_frame_dbuffer_abort(&s->in_audio_buffer);
	
	av_frame_free(&frame);
	
	//fprintf(stderr, "_audio_decode_thread(): Ending\n");
	
	return(NULL);
}

static void *_audio_scaler_thread(void *arg)
{
	av_ffmpeg_t *s = (av_ffmpeg_t *) arg;
	AVFrame *frame, *oframe;
	int64_t pts, next_pts;
	uint8_t const *data[AV_NUM_DATA_POINTERS];
	int r, count, drop;
	
	//fprintf(stderr, "_audio_scaler_thread(): Starting\n");
	
	/* Fetch audio frames and pass them through the resampler */
	while((frame = _frame_dbuffer_flip(&s->in_audio_buffer)) != NULL)
	{
		pts = frame->best_effort_timestamp;
		drop = 0;
		
		if(pts != AV_NOPTS_VALUE)
		{
			pts      = av_rescale_q(pts, s->audio_stream->time_base, s->audio_time_base);
			pts     -= s->audio_start_time;
			next_pts = pts + frame->nb_samples;
			
			if(next_pts <= 0)
			{
				/* This frame is in the past. Skip it */
				av_frame_unref(frame);
				continue;
			}
			
			if(pts < -s->allowed_error)
			{
				/* Trim this frame */
				drop = -pts;
				//swr_drop_input(s->swr_ctx, -pts); /* It would be nice if this existed */
			}
			else if(pts > s->allowed_error)
			{
				/* This frame is in the future. Send silence to fill the gap */
				r = swr_inject_silence(s->swr_ctx, pts);
				s->audio_start_time += pts;
			}
		}
		
		count = frame->nb_samples;
		
		count -= drop;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
		_audio_offset(
			data,
			(const uint8_t **) frame->data,
			drop,
			s->audio_codec_ctx->ch_layout.nb_channels,
			s->audio_codec_ctx->sample_fmt
		);
#else
		_audio_offset(
			data,
			(const uint8_t **) frame->data,
			drop,
			s->audio_codec_ctx->channels,
			s->audio_codec_ctx->sample_fmt
		);
#endif
		
		do
		{
			oframe = _frame_dbuffer_back_buffer(&s->out_audio_buffer);
			r = swr_convert(
				s->swr_ctx,
				oframe->data,
				s->out_frame_size,
				count ? data : NULL,
				count
			);
			if(r == 0) break;
			
			oframe->nb_samples = r;
			
			_frame_dbuffer_ready(&s->out_audio_buffer, 0);
			
			s->audio_start_time += count;
			count = 0;
		}
		while(r > 0);
		
		av_frame_unref(frame);
	}
	
	_frame_dbuffer_abort(&s->out_audio_buffer);
	
	//fprintf(stderr, "_audio_scaler_thread(): Ending\n");
	
	return(NULL);
}

static int16_t *_ffmpeg_read_audio(void *ctx, size_t *samples)
{
	av_ffmpeg_t *s = ctx;
	AVFrame *frame;
	
	if(s->audio_stream == NULL || s->paused)
	{
		return(NULL);
	}
	
	frame = _frame_dbuffer_flip(&s->out_audio_buffer);
	if(!frame)
	{
		/* EOF or abort */
		s->audio_eof = 1;
		return(NULL);
	}
	
	*samples = frame->nb_samples;
	
	return((int16_t *) frame->data[0]);
}

static int _ffmpeg_eof(void *ctx)
{
	av_ffmpeg_t *s = ctx;
	
	if((s->video_stream && !s->video_eof) ||
	   (s->audio_stream && !s->audio_eof))
	{
		return(0);
	}
	
	return(1);
}

static int _ffmpeg_close(void *ctx)
{
	av_ffmpeg_t *s = ctx;
	
	s->thread_abort = 1;
	_packet_queue_abort(s, &s->video_queue);
	_packet_queue_abort(s, &s->audio_queue);
	
	pthread_join(s->input_thread, NULL);
	
	if(s->video_stream != NULL)
	{
		_frame_dbuffer_abort(&s->in_video_buffer);
		_frame_dbuffer_abort(&s->out_video_buffer);
		
		pthread_join(s->video_decode_thread, NULL);
		pthread_join(s->video_scaler_thread, NULL);
		
		_packet_queue_free(s, &s->video_queue);
		_frame_dbuffer_free(&s->in_video_buffer);
		
		av_freep(&s->out_video_buffer.frame[0]->data[0]);
		av_freep(&s->out_video_buffer.frame[1]->data[0]);
		_frame_dbuffer_free(&s->out_video_buffer);
		
		avcodec_free_context(&s->video_codec_ctx);
		sws_freeContext(s->sws_ctx);
	}
	
	if(s->audio_stream != NULL)
	{
		_frame_dbuffer_abort(&s->in_audio_buffer);
		_frame_dbuffer_abort(&s->out_audio_buffer);
		
		pthread_join(s->audio_decode_thread, NULL);
		pthread_join(s->audio_scaler_thread, NULL);
		
		_packet_queue_free(s, &s->audio_queue);
		_frame_dbuffer_free(&s->in_audio_buffer);
		
		//av_freep(&s->out_audio_buffer.frame[0]->data[0]);
		//av_freep(&s->out_audio_buffer.frame[1]->data[0]);
		_frame_dbuffer_free(&s->out_audio_buffer);
		
		avcodec_free_context(&s->audio_codec_ctx);
		swr_free(&s->swr_ctx);
	}
	
	avformat_close_input(&s->format_ctx);
	
	pthread_cond_destroy(&s->cond);
	pthread_mutex_destroy(&s->mutex);
	
	free(s);
	
	return(HACKTV_OK);
}

int av_ffmpeg_open(vid_t *vid, void *ctx, char *input_url, char *format, char *options)
{
	av_ffmpeg_t *s;
	vid_config_t *conf = ctx;
	av_t *av = &vid->av;

	const AVInputFormat *fmt = NULL;
	const AVCodec *codec;
	AVDictionary *opts = NULL;
	AVRational time_base;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
	AVChannelLayout dst_ch_layout = AV_CHANNEL_LAYOUT_STEREO;
#endif
	int64_t start_time = 0;
	int r, i, ws;

	/* Default ratio */
	float source_ratio;

	/* Filter declarations */
	char *_filter_args;
	char *_filter_def;
	
	s = calloc(1, sizeof(av_ffmpeg_t));
	if(!s)
	{
		return(HACKTV_OUT_OF_MEMORY);
	}

	s->paused = 0;
	
	s->av = av;
	
	s->av = av;
	
	/* Use 'pipe:' for stdin */
	if(strcmp(input_url, "-") == 0)
	{
		input_url = "pipe:";
	}
	
	if(format != NULL)
	{
		fmt = av_find_input_format(format);
	}
	
	if(options)
	{
		av_dict_parse_string(&opts, options, "=", ":", 0);
	}
	
	/* Open the video */
	if((r = avformat_open_input(&s->format_ctx, input_url, fmt, &opts)) < 0)
	{
		fprintf(stderr, "Error opening file '%s'\n", input_url);
		_print_ffmpeg_error(r);
		return(HACKTV_ERROR);
	}
	
	/* Read stream info from the file */
	if(avformat_find_stream_info(s->format_ctx, NULL) < 0)
	{
		fprintf(stderr, "Error reading stream information from file\n");
		return(HACKTV_ERROR);
	}
	
	/* Dump some useful information to stderr */
	fprintf(stderr, "Opening '%s'...\n", input_url);
	av_dump_format(s->format_ctx, 0, input_url, 0);
	
	/* Find the first video and audio streams */
	/* TODO: Allow the user to select streams by number or name */
	s->video_stream = NULL;
	s->audio_stream = NULL;
	s->subtitle_stream = NULL;
	
	for(i = 0; i < s->format_ctx->nb_streams; i++)
	{
		if(s->video_stream == NULL && s->format_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO)
		{
			s->video_stream = s->format_ctx->streams[i];
		}
		
		if(av->sample_rate.num && s->audio_stream == NULL && s->format_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_AUDIO)
		{
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
			if(s->format_ctx->streams[i]->codecpar->ch_layout.nb_channels <= 0) continue;
#else
			if(s->format_ctx->streams[i]->codecpar->channels <= 0) continue;
#endif
			s->audio_stream = s->format_ctx->streams[i];
		}
		
		if(s->subtitle_stream == NULL && s->format_ctx->streams[i]->codecpar->codec_type == AVMEDIA_TYPE_SUBTITLE)
		{
			s->subtitle_stream = s->format_ctx->streams[conf->txsubtitles >= i && conf->txsubtitles < s->format_ctx->nb_streams? conf->txsubtitles : i];
			s->subtitle_stream = s->format_ctx->streams[conf->subtitles >= i && conf->subtitles < s->format_ctx->nb_streams? conf->subtitles : i];
		}
	}
	
	/* At minimum we need either a video or audio stream */
	if(s->video_stream == NULL && s->audio_stream == NULL)
	{
		fprintf(stderr, "No video or audio streams found\n");
		return(HACKTV_ERROR);
	}
	
	if(s->video_stream != NULL)
	{
		fprintf(stderr, "Using video stream %d.\n", s->video_stream->index);
		
		/* Create the video's time_base using the current TV mode's frames per second.
		 * Numerator and denominator are swapped as ffmpeg uses seconds per frame. */
		s->video_time_base.num = av->frame_rate.den;
		s->video_time_base.den = av->frame_rate.num;
		
		/* Use the video's start time as the reference */
		time_base = s->video_stream->time_base;
		start_time = s->video_stream->start_time;
		
		/* Get a pointer to the codec context for the video stream */
		s->video_codec_ctx = avcodec_alloc_context3(NULL);
		if(!s->video_codec_ctx)
		{
			return(HACKTV_OUT_OF_MEMORY);
		}
		
		if(avcodec_parameters_to_context(s->video_codec_ctx, s->video_stream->codecpar) < 0)
		{
			return(HACKTV_ERROR);
		}
		
		s->video_codec_ctx->thread_count = 0; /* Let ffmpeg decide number of threads */
		
		/* Find the decoder for the video stream */
		codec = avcodec_find_decoder(s->video_codec_ctx->codec_id);
		if(codec == NULL)
		{
			fprintf(stderr, "Unsupported video codec\n");
			return(HACKTV_ERROR);
		}
		
		/* Open video codec */
		if(avcodec_open2(s->video_codec_ctx, codec, NULL) < 0)
		{
			fprintf(stderr, "Error opening video codec\n");
			return(HACKTV_ERROR);
		}
		
		/* Video filter starts here */
			
		AVFilterGraph *vfilter_graph;

		/* Deprecated - to be removed in later versions */
		#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
		avfilter_register_all();
		#endif
		
		const AVFilter *vbuffersrc  = avfilter_get_by_name("buffer");
		const AVFilter *vbuffersink = avfilter_get_by_name("buffersink");
		AVFilterInOut *vinputs  = avfilter_inout_alloc();
		AVFilterInOut *voutputs = avfilter_inout_alloc();
		vfilter_graph = avfilter_graph_alloc();

		asprintf(&_filter_args,"video_size=%dx%d:pix_fmt=%d:time_base=%d/%d:pixel_aspect=%d/%d",
			s->video_codec_ctx->width, s->video_codec_ctx->height, s->video_codec_ctx->pix_fmt,
			s->video_stream->r_frame_rate.num, s->video_stream->r_frame_rate.den,
			s->video_codec_ctx->sample_aspect_ratio.num, s->video_codec_ctx->sample_aspect_ratio.den);

		if(avfilter_graph_create_filter(&s->vbuffersrc_ctx, vbuffersrc, "in",_filter_args, NULL, vfilter_graph) < 0) 
		{
			fprintf(stderr, "Cannot create video buffer source\n");
			return(HACKTV_ERROR);
		}
		
		if(avfilter_graph_create_filter(&s->vbuffersink_ctx, vbuffersink, "out", NULL, NULL, vfilter_graph) < 0) 
		{
			fprintf(stderr,"Cannot create video buffer sink\n");
			return(HACKTV_ERROR);
		}
	
		/* Endpoints for the filter graph. */
		voutputs->name       = av_strdup("in");
		voutputs->filter_ctx = s->vbuffersrc_ctx;
		voutputs->pad_idx    = 0;
		voutputs->next       = NULL;
		
		vinputs->name       = av_strdup("out");
		vinputs->filter_ctx = s->vbuffersink_ctx;
		vinputs->pad_idx    = 0;
		vinputs->next       = NULL;
				
		source_ratio = (float) s->video_codec_ctx->width / (float) s->video_codec_ctx->height;
		ws = source_ratio >= (14.0 / 9.0) ? 1 : 0;	
		
		/* Default states */
		asprintf(&_filter_def,"[in]null[out]");
		
		if(ws)
		{
			int video_width;
			video_width = av->height * (4.0 / 3.0);

			if(conf->letterbox)
			{
				asprintf(&_filter_def,"[in]pad = 'iw:iw / (%i / %i) : 0 : (oh - ih) / 2', scale = %i:%i[out]", video_width, av->height, s->video_codec_ctx->width, s->video_codec_ctx->height);
			}
			else if(conf->pillarbox)
			{
				asprintf(&_filter_def,"[in]crop = out_w = in_h * (4.0 / 3.0) : out_h = in_h, scale = %i:%i[out]", s->video_codec_ctx->width, s->video_codec_ctx->height);
			}
			else
			{
				/* Calculate letterbox padding for widescreen videos */ 
				video_width = av->height * (16.0 / 9.0);

				if((float) video_width / (float) av->height <= source_ratio)
				{
					asprintf(&_filter_def,"[in]pad = 'iw:iw / (%i/%i) : 0 : (oh-ih) / 2', scale = %i:%i[out]", video_width, av->height, s->video_codec_ctx->width, s->video_codec_ctx->height);
				}
				else
				{
					asprintf(&_filter_def,"[in]pad = 'ih * (%i / %i) : ih : (ow-iw) / 2 : 0', scale = %i:%i[out]", video_width, av->height, s->video_codec_ctx->width, s->video_codec_ctx->height);
				}
			}
		}
		
		if(avfilter_graph_parse_ptr(vfilter_graph, _filter_def, &vinputs, &voutputs, NULL) < 0)
		{
			fprintf(stderr, "Cannot parse filter graph\n");
			return(HACKTV_ERROR);
		}
		
		if(avfilter_graph_config(vfilter_graph, NULL) < 0) 
		{
			fprintf(stderr, "Cannot configure filter graph\n");
			return(HACKTV_ERROR);
		}
		
		avfilter_inout_free(&vinputs);
		avfilter_inout_free(&voutputs);
		
		/* Video filter ends here */
		
		/* Initialise SWS context for software scaling */
		s->sws_ctx = sws_getContext(
			s->video_codec_ctx->width,
			s->video_codec_ctx->height,
			s->video_codec_ctx->pix_fmt,
			av->width,
			av->height,
			AV_PIX_FMT_RGB32,
			SWS_BICUBIC,
			NULL,
			NULL,
			NULL
		);
		
		if(!s->sws_ctx)
		{
			return(HACKTV_OUT_OF_MEMORY);
		}
		
		s->video_eof = 0;
	}
	else
	{
		fprintf(stderr, "No video streams found.\n");
	}
	
	if(s->audio_stream != NULL)
	{
		fprintf(stderr, "Using audio stream %d.\n", s->audio_stream->index);
		
		/* Get a pointer to the codec context for the video stream */
		s->audio_codec_ctx = avcodec_alloc_context3(NULL);
		if(!s->audio_codec_ctx)
		{
			return(HACKTV_ERROR);
		}
		
		if(avcodec_parameters_to_context(s->audio_codec_ctx, s->audio_stream->codecpar) < 0)
		{
			return(HACKTV_ERROR);
		}
		
		s->audio_codec_ctx->thread_count = 0; /* Let ffmpeg decide number of threads */
		
		/* Find the decoder for the audio stream */
		codec = avcodec_find_decoder(s->audio_codec_ctx->codec_id);
		if(codec == NULL)
		{
			fprintf(stderr, "Unsupported audio codec\n");
			return(HACKTV_ERROR);
		}
		
		/* Open audio codec */
		if(avcodec_open2(s->audio_codec_ctx, codec, NULL) < 0)
		{
			fprintf(stderr, "Error opening audio codec\n");
			return(HACKTV_ERROR);
		}
		
		/* Audio filter graph here */
		AVFilterGraph *afilter_graph;
		
		/* Deprecated - to be removed in later versions */
		#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
		avfilter_register_all();
		#endif
		
		const AVFilter *abuffersrc  = avfilter_get_by_name("abuffer");
		const AVFilter *abuffersink = avfilter_get_by_name("abuffersink");
		AVFilterInOut *aoutputs = avfilter_inout_alloc();
		AVFilterInOut *ainputs  = avfilter_inout_alloc();
		afilter_graph = avfilter_graph_alloc();

		#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
		asprintf(&_filter_args, "time_base=%d/%d:sample_rate=%d:sample_fmt=%s:channel_layout=0x%" PRIx64,
			s->audio_codec_ctx->time_base.num, s->audio_codec_ctx->time_base.den, s->audio_codec_ctx->sample_rate,
			av_get_sample_fmt_name(s->audio_codec_ctx->sample_fmt),
			s->audio_codec_ctx->ch_layout.u.mask);
		#else
		asprintf(&_filter_args, "time_base=%d/%d:sample_rate=%d:sample_fmt=%s:channel_layout=0x%" PRIx64,
			s->audio_codec_ctx->time_base.num, s->audio_codec_ctx->time_base.den, s->audio_codec_ctx->sample_rate,
			av_get_sample_fmt_name(s->audio_codec_ctx->sample_fmt),
			s->audio_codec_ctx->channel_layout);
		#endif
	
		if(avfilter_graph_create_filter(&s->abuffersrc_ctx, abuffersrc, "in", _filter_args, NULL, afilter_graph) < 0) 
		{
			fprintf(stderr, "Cannot create audio buffer source\n");
			return(HACKTV_ERROR);
		}
		
		if(avfilter_graph_create_filter(&s->abuffersink_ctx, abuffersink, "out", NULL, NULL, afilter_graph) < 0) 
		{
			fprintf(stderr, "Cannot create audio buffer sink\n");
			return(HACKTV_ERROR);
		}

		/* Endpoints for the audio filter graph. */
		aoutputs->name       = av_strdup("in");
		aoutputs->filter_ctx = s->abuffersrc_ctx;
		aoutputs->pad_idx    = 0;
		aoutputs->next       = NULL;

		ainputs->name       = av_strdup("out");
		ainputs->filter_ctx = s->abuffersink_ctx;
		ainputs->pad_idx    = 0;
		ainputs->next       = NULL;
		
		char str_buf[5];
		sprintf(str_buf,"%s", av_get_sample_fmt_name(s->audio_codec_ctx->sample_fmt));
		asprintf(&_filter_def,
				"[in]%s[downmix],[downmix]volume=%f:precision=%s[out]",
				conf->downmix ? "pan=stereo|FL < FC + 0.30*FL + 0.30*BL|FR < FC + 0.30*FR + 0.30*BR" : "anull",
				conf->volume,
				str_buf[0] == 'f' ? "float" : str_buf[0] == 'd' ? "double" : "fixed"
		);
		
		if (avfilter_graph_parse_ptr(afilter_graph, _filter_def, &ainputs, &aoutputs, NULL) < 0)
		{
			fprintf(stderr,"Cannot parse filter graph %s\n", _filter_def);
			return(HACKTV_ERROR);
		}
		
		if (avfilter_graph_config(afilter_graph, NULL) < 0) 
		{
			printf("Cannot configure filter graph\n");
			return(HACKTV_ERROR);
		}
		
		avfilter_inout_free(&ainputs);
		avfilter_inout_free(&aoutputs);

		/* Audio filter ends here */
		
		/* Create the audio time_base using the source sample rate */
		s->audio_time_base.num = 1;
		s->audio_time_base.den = s->audio_codec_ctx->sample_rate;
		
		/* Use the audio's start time as the reference if no video was detected */
		if(s->video_stream == NULL)
		{
			time_base = s->audio_stream->time_base;
			start_time = s->audio_stream->start_time;
		}
		
		/* Prepare the resampler */
		s->swr_ctx = swr_alloc();
		if(!s->swr_ctx)
		{
			return(HACKTV_OUT_OF_MEMORY);
		}
		
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
		AVChannelLayout default_ch_layout;
		if(!s->audio_codec_ctx->ch_layout.nb_channels)
		{
			/* Set the default layout for codecs that don't specify any */
			av_channel_layout_default(&default_ch_layout, s->audio_codec_ctx->ch_layout.nb_channels);
			s->audio_codec_ctx->ch_layout = default_ch_layout;
		}
		
		av_opt_set_int(s->swr_ctx, "in_channel_layout",    conf->downmix ? AV_CH_LAYOUT_STEREO : s->audio_codec_ctx->ch_layout.u.mask, 0);
		av_opt_set_int(s->swr_ctx, "in_sample_rate",       s->audio_codec_ctx->sample_rate, 0);
		av_opt_set_sample_fmt(s->swr_ctx, "in_sample_fmt", s->audio_codec_ctx->sample_fmt, 0);

		// av_opt_set_chlayout(s->swr_ctx, "in_chlayout",     conf->downmix ? AV_CH_LAYOUT_STEREO : &s->audio_codec_ctx->ch_layout, 0);
		// av_opt_set_int(s->swr_ctx, "in_sample_rate",       s->audio_codec_ctx->sample_rate, 0);
		// av_opt_set_sample_fmt(s->swr_ctx, "in_sample_fmt", s->audio_codec_ctx->sample_fmt, 0);
		
		av_opt_set_chlayout(s->swr_ctx, "out_chlayout",    &dst_ch_layout, 0);
#else
		if(!s->audio_codec_ctx->channel_layout)
		{
			/* Set the default layout for codecs that don't specify any */
			s->audio_codec_ctx->channel_layout = av_get_default_channel_layout(s->audio_codec_ctx->channels);
		}
		
		av_opt_set_int(s->swr_ctx, "in_channel_layout",    conf->downmix ? AV_CH_LAYOUT_STEREO : s->audio_codec_ctx->channel_layout, 0);
		av_opt_set_int(s->swr_ctx, "in_sample_rate",       s->audio_codec_ctx->sample_rate, 0);
		av_opt_set_sample_fmt(s->swr_ctx, "in_sample_fmt", s->audio_codec_ctx->sample_fmt, 0);
		
		av_opt_set_int(s->swr_ctx, "out_channel_layout",    AV_CH_LAYOUT_STEREO, 0);
#endif
		
		av_opt_set_int(s->swr_ctx, "out_sample_rate",       av->sample_rate.num / av->sample_rate.den, 0);
		av_opt_set_sample_fmt(s->swr_ctx, "out_sample_fmt", AV_SAMPLE_FMT_S16, 0);
		
		if(swr_init(s->swr_ctx) < 0)
		{
			fprintf(stderr, "Failed to initialise the resampling context\n");
			return(HACKTV_ERROR);
		}
		
		s->audio_eof = 0;
	}
	else
	{
		fprintf(stderr, "No audio streams found.\n");
	}
	
	/* Free filter graph memory */
	free(_filter_def);
	free(_filter_args);
	
	if(conf->subtitles || conf->txsubtitles)
	{
		if(s->subtitle_stream != NULL)
		{
			subs_init_ffmpeg(&s->av_sub);
			
			/* Initialise fonts here */
			if(font_init(av, 38, source_ratio, conf) !=0)
			{
				return(HACKTV_ERROR);
			};
			
			s->font[TEXT_SUBTITLE] = av->av_font;
			s->font[TEXT_SUBTITLE]->video_width += 2;

			fprintf(stderr, "Using subtitle stream %d.\n", s->subtitle_stream->index);
			
			/* Get a pointer to the codec context for the subtitle stream */
			s->subtitle_codec_ctx = avcodec_alloc_context3(NULL);
			if(!s->subtitle_codec_ctx)
			{
				return(HACKTV_OUT_OF_MEMORY);
			}
			
			if(avcodec_parameters_to_context(s->subtitle_codec_ctx, s->subtitle_stream->codecpar) < 0)
			{
				return(HACKTV_ERROR);
			}
			
			s->subtitle_codec_ctx->thread_count = 0; /* Let ffmpeg decide number of threads */
			s->subtitle_codec_ctx->pkt_timebase = s->subtitle_stream->time_base;
			
			/* Find the decoder for the subtitle stream */
			const AVCodec *codec = avcodec_find_decoder(s->subtitle_codec_ctx->codec_id);
			if(codec == NULL)
			{
				fprintf(stderr, "Unsupported subtitle codec\n");
				return(HACKTV_ERROR);
			}
			
			/* Open subtitle codec */
			if(avcodec_open2(s->subtitle_codec_ctx, codec, NULL) < 0)
			{
				fprintf(stderr, "Error opening subtitle codec\n");
				return(HACKTV_ERROR);
			}
			
			s->subtitle_eof = 0;
		}
		else
		{
			fprintf(stderr, "No subtitle streams found.\n");
			
			/* Initialise subtitles - here because it's already supplied with the filename for video */
			/* Should really be moved somewhere else */
			if(conf->subtitles || conf->txsubtitles)
			{
				if(subs_init_file(input_url, &s->av_sub) != HACKTV_OK)
				{
					conf->subtitles = 0;
					conf->txsubtitles = 0;
					return(HACKTV_ERROR);
				}
				
				/* Initialise fonts here */
				if(font_init(av, 38, source_ratio, conf) < 0)
				{
					conf->subtitles = 0;
					conf->txsubtitles = 0;
					return(HACKTV_ERROR);
				}
				
				s->font[TEXT_SUBTITLE] = av->av_font;
				s->font[TEXT_SUBTITLE]->video_width += 2;
			}
		}
	}
	
	if(start_time == AV_NOPTS_VALUE)
	{
		start_time = 0;
	}
	
	/* Seek stuff here */
	int64_t request_timestamp = (60.0 * conf->position) / av_q2d(time_base) + start_time;
	
	/* Calculate the start time for each stream */
	if(s->video_stream != NULL)
	{
		if (conf->position > 0) 
		{
			s->video_start_time = av_rescale_q(request_timestamp, time_base, s->video_time_base);
			avformat_seek_file(s->format_ctx, s->video_stream->index, INT64_MIN, request_timestamp, INT64_MAX, 0);
		}
		else
		{
			s->video_start_time = av_rescale_q(start_time, time_base, s->video_time_base);
		}
	}
	
	if(s->audio_stream != NULL)
	{
		s->audio_start_time = av_rescale_q(conf->position ? request_timestamp : start_time, time_base, s->audio_time_base);
	}
	
	if(conf->timestamp)
	{
		conf->timestamp = time(0);
		
		if(font_init(av, 40, source_ratio, conf) != VID_OK)
		{
			conf->timestamp = 0;
		};
		
		s->font[TEXT_TIMESTAMP] = av->av_font;
		s->font[TEXT_TIMESTAMP]->video_width += 2;
	}
	
	/* Calculate ratio */
	float ratio = conf->pillarbox || conf->letterbox ? (4.0 / 3.0 ): ws ? (16.0 / 9.0) : (4.0 / 3.0);

	/* Load logo */
	if(conf->logo)
	{
		if(load_png(&s->av_logo, av->width, av->height, conf->logo, 0.75, ratio, IMG_LOGO) == HACKTV_ERROR)
		{
			conf->logo = NULL;
		}
	}
	
	if(load_png(&s->media_icons[0], av->width, av->height, "play", 1, ratio, IMG_MEDIA) != HACKTV_OK)
	{
		fprintf(stderr, "Error loading media icons.\n");
		return(HACKTV_ERROR);
	}
	
	if(load_png(&s->media_icons[1], av->width, av->height, "pause", 1, ratio, IMG_MEDIA) != HACKTV_OK)
	{
		fprintf(stderr, "Error loading media icons.\n");
		return(HACKTV_ERROR);
	}
		
	/* Register the callback functions */
	s->vid_conf = &vid->conf;
	s->vid_tt = &vid->tt;
	s->width = av->width;
	s->height = av->height;

	av->av_source_ctx = s;
	av->read_video = _ffmpeg_read_video;
	av->read_audio = _ffmpeg_read_audio;
	av->eof = _ffmpeg_eof;
	av->close = _ffmpeg_close;
	
	/* Start the threads */
	s->thread_abort = 0;
	pthread_mutex_init(&s->mutex, NULL);
	pthread_cond_init(&s->cond, NULL);
	_packet_queue_init(s, &s->video_queue);
	_packet_queue_init(s, &s->audio_queue);
	
	if(s->video_stream != NULL)
	{
		_frame_dbuffer_init(&s->in_video_buffer);
		_frame_dbuffer_init(&s->out_video_buffer);
		
		/* Allocate memory for the output frame buffers */
		for(i = 0; i < 2; i++)
		{
			s->out_video_buffer.frame[i]->width = av->width;
			s->out_video_buffer.frame[i]->height = av->height;
			
			r = av_image_alloc(
				s->out_video_buffer.frame[i]->data,
				s->out_video_buffer.frame[i]->linesize,
				av->width, av->height,
				AV_PIX_FMT_RGB32, av_cpu_max_align()
			);
		}
		
		r = pthread_create(&s->video_decode_thread, NULL, &_video_decode_thread, (void *) s);
		if(r != 0)
		{
			fprintf(stderr, "Error starting video decoder thread.\n");
			return(HACKTV_ERROR);
		}
		
		r = pthread_create(&s->video_scaler_thread, NULL, &_video_scaler_thread, (void *) s);
		if(r != 0)
		{
			fprintf(stderr, "Error starting video scaler thread.\n");
			return(HACKTV_ERROR);
		}
	}
	
	if(s->audio_stream != NULL)
	{
		_frame_dbuffer_init(&s->in_audio_buffer);
		_frame_dbuffer_init(&s->out_audio_buffer);
		
		/* Calculate the number of samples needed for output */
		s->out_frame_size = av_rescale_q_rnd(
			s->audio_codec_ctx->frame_size, /* Can this be trusted? */
			(AVRational) { av->sample_rate.num, av->sample_rate.den },
			(AVRational) { s->audio_codec_ctx->sample_rate, 1 },
			AV_ROUND_UP
		);
		
		if(s->out_frame_size <= 0)
		{
			s->out_frame_size = av->sample_rate.num / av->sample_rate.den;
		}
		
		/* Calculate the allowed error in input samples, +/- 20ms */
		s->allowed_error = av_rescale_q(AV_TIME_BASE * 0.020, AV_TIME_BASE_Q, s->audio_time_base);
		
		for(i = 0; i < 2; i++)
		{
			s->out_audio_buffer.frame[i]->format = AV_SAMPLE_FMT_S16;
#if LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(59, 24, 100)
			s->out_audio_buffer.frame[i]->ch_layout = (AVChannelLayout) AV_CHANNEL_LAYOUT_STEREO;
#else
			s->out_audio_buffer.frame[i]->channel_layout = AV_CH_LAYOUT_STEREO;
#endif
			s->out_audio_buffer.frame[i]->sample_rate = av->sample_rate.num / av->sample_rate.den;
			s->out_audio_buffer.frame[i]->nb_samples = s->out_frame_size;
			
			r = av_frame_get_buffer(s->out_audio_buffer.frame[i], 0);
			if(r < 0)
			{
				fprintf(stderr, "Error allocating output audio buffer %d\n", i);
				return(HACKTV_OUT_OF_MEMORY);
			}
		}
		
		r = pthread_create(&s->audio_decode_thread, NULL, &_audio_decode_thread, (void *) s);
		if(r != 0)
		{
			fprintf(stderr, "Error starting audio decoder thread.\n");
			return(HACKTV_ERROR);
		}
		
		r = pthread_create(&s->audio_scaler_thread, NULL, &_audio_scaler_thread, (void *) s);
		if(r != 0)
		{
			fprintf(stderr, "Error starting audio resampler thread.\n");
			return(HACKTV_ERROR);
		}
	}
	
	r = pthread_create(&s->input_thread, NULL, &_input_thread, (void *) s);
	if(r != 0)
	{
		fprintf(stderr, "Error starting input thread.\n");
		return(HACKTV_ERROR);
	}
	
	return(HACKTV_OK);
}

void av_ffmpeg_init(void)
{
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
	av_register_all();
#endif
	avdevice_register_all();
	avformat_network_init();
}

void av_ffmpeg_deinit(void)
{
	avformat_network_deinit();
}

