/*
 * Copyright (C) 2007 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id$
 */

#include "ipf.h"


void printfieldhdr(words, field)
wordtab_t *words, *field;
{
	wordtab_t *w;
	char *s, *t;
	int i;

	if (field->w_value == -2) {
		for (i = 0, w = words; w->w_word != NULL; ) {
			if (w->w_value > 0) {
				printfieldhdr(words, w);
				w++;
				if (w->w_value > 0)
					putchar('\t');
			} else {
				w++;
			}
		}
		return;
	}

	for (w = words; w->w_word != NULL; w++) {
		if (w->w_value == field->w_value) {
			if (w->w_word == field->w_word) {
				s = strdup(w->w_word);
			} else {
				s = NULL;
			}

			if ((w->w_word != field->w_word) || (s == NULL)) {
				printf("%s", field->w_word);
			} else {
				for (t = s; *t != '\0'; t++) {
					if (isalpha(*t) && islower(*t))
						*t = toupper(*t);
				}
				printf("%s", s);
				free(s);
			}
		}
	}
}
