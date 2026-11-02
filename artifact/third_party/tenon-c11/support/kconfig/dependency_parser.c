/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024 The TenonOS Authors
 */

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libgen.h>

#include "lkc.h"

/*
 * elib_dependency generate a dependency file of all external libs. Each line in format:
 * 		A B: if A depends on B,
 * 		A: if A doesn't depend on any other LIBls.
 */
int elib_dependency()
{

	struct menu *render_menu = NULL;
	struct gstr orig_file;
	struct file *cur_file;
	char *cur_lib, *out_name, *elib_base;
	FILE *out;
	struct expr *e;

	elib_base = getenv("KCONFIG_ELIB_BASE");
	if (!elib_base)
	{
		fprintf(stderr, "\n***can't find env KCONFIG_ELIB_BASE\n");
		return 1;
	}

	out_name = conf_get_dependency_file_name("elibs");
	if (!out_name)
	{
		fprintf(stderr, "\n***get dependency file name failed: elibs\n");
		return 1;
	}
	out = fopen(out_name, "w");
	if (!out)
	{
		fprintf(stderr, "\n***open dependency file failed: %s\n", out_name);
		return 1;
	}

	orig_file = str_new();
	for (cur_lib = strtok(getenv("KCONFIG_ELIB_DIRS"), " "); cur_lib != NULL; cur_lib = strtok(NULL, " "))
	{
		str_clear(&orig_file);
		str_append(&orig_file, cur_lib);
		str_append(&orig_file, "/Config.uk");
		cur_file = file_lookup(str_get(&orig_file), false);
		if (!cur_file)
		{
			fprintf(stderr, "\n***config file didn't parsed: %s\n\n", str_get(&orig_file));
			return 1;
		}
		render_menu = cur_file->rootm;
		if (!render_menu || !render_menu->sym)
		{
			fprintf(stderr, "\n***config file in wrong format: %s\n\n", cur_file->name);
			return 1;
		}

		/* output dep to tmpfile */
		if (!render_menu->dep)
		{
			fprintf(out, "%s %s\n", cur_lib, cur_lib);
			continue;
		}
		e = render_menu->dep;
		while (e != NULL)
		{
			if (e->type == E_SYMBOL)
			{
				output_dependency(out, e->left.sym, elib_base, cur_lib);
				break;
			}
			else if (e->right.expr && e->right.expr->type == E_SYMBOL)
			{
				output_dependency(out, e->right.expr->left.sym, elib_base, cur_lib);
			}
			e = e->left.expr;
		}
	}

	str_free(&orig_file);
	free(out_name);
	fclose(out);
	return 0;
}

void output_dependency(FILE *out, struct symbol *sym, char *prefix, char *orig)
{
	char *dep_lib;
	if (!sym)
		return;

	dep_lib = xstrdup(sym->prop->file->name);
	/* only output elib symbols, ignore other depends */
	if (xstrcontains(dep_lib, prefix)) {
		fprintf(out, "%s %s\n", dirname(dep_lib), orig);
	} else {
		fprintf(out, "%s %s\n", orig, orig);
	}
	free(dep_lib);
}
