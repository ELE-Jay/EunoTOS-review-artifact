// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 */

#include <sys/mman.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "lkc.h"

/* return true if 'path' exists, false otherwise */
static bool is_present(const char *path)
{
	struct stat st;

	return !stat(path, &st);
}

/* return true if 'path' exists and it is a directory, false otherwise */
static bool is_dir(const char *path)
{
	struct stat st;

	if (stat(path, &st))
		return 0;

	return S_ISDIR(st.st_mode);
}

/* return true if the given two files are the same, false otherwise */
static bool is_same(const char *file1, const char *file2)
{
	int fd1, fd2;
	struct stat st1, st2;
	void *map1, *map2;
	bool ret = false;

	fd1 = open(file1, O_RDONLY);
	if (fd1 < 0)
		return ret;

	fd2 = open(file2, O_RDONLY);
	if (fd2 < 0)
		goto close1;

	ret = fstat(fd1, &st1);
	if (ret)
		goto close2;
	ret = fstat(fd2, &st2);
	if (ret)
		goto close2;

	if (st1.st_size != st2.st_size)
		goto close2;

	map1 = mmap(NULL, st1.st_size, PROT_READ, MAP_PRIVATE, fd1, 0);
	if (map1 == MAP_FAILED)
		goto close2;

	map2 = mmap(NULL, st2.st_size, PROT_READ, MAP_PRIVATE, fd2, 0);
	if (map2 == MAP_FAILED)
		goto close2;

	if (bcmp(map1, map2, st1.st_size))
		goto close2;

	ret = true;
close2:
	close(fd2);
close1:
	close(fd1);

	return ret;
}

/*
 * Create the parent directory of the given path.
 *
 * For example, if 'include/config/auto.conf' is given, create 'include/config'.
 */
static int make_parent_dir(const char *path)
{
	char tmp[PATH_MAX + 1];
	char *p;

	strncpy(tmp, path, sizeof(tmp));
	tmp[sizeof(tmp) - 1] = 0;

	/* Remove the base name. Just return if nothing is left */
	p = strrchr(tmp, '/');
	if (!p)
		return 0;
	*(p + 1) = 0;

	/* Just in case it is an absolute path */
	p = tmp;
	while (*p == '/')
		p++;

	while ((p = strchr(p, '/'))) {
		*p = 0;

		/* skip if the directory exists */
		if (!is_dir(tmp) && mkdir(tmp, 0755))
			return -1;

		*p = '/';
		while (*p == '/')
			p++;
	}

	return 0;
}

static char depfile_path[PATH_MAX];
static size_t depfile_prefix_len;

/* touch depfile for symbol 'name' */
static int conf_touch_dep(const char *name)
{
	int fd, ret;
	const char *s;
	char *d, c;

	/* check overflow: prefix + name + ".h" + '\0' must fit in buffer. */
	if (depfile_prefix_len + strlen(name) + 3 > sizeof(depfile_path))
		return -1;

	d = depfile_path + depfile_prefix_len;
	s = name;

	while ((c = *s++))
		*d++ = (c == '_') ? '/' : tolower(c);
	strcpy(d, ".h");

	/* Assume directory path already exists. */
	fd = open(depfile_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		if (errno != ENOENT)
			return -1;

		ret = make_parent_dir(depfile_path);
		if (ret)
			return ret;

		/* Try it again. */
		fd = open(depfile_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd == -1)
			return -1;
	}
	close(fd);

	return 0;
}

struct conf_printer {
	void (*print_symbol)(FILE *, struct symbol *, const char *, void *);
	void (*print_comment)(FILE *, const char *, void *);
};

static void conf_warning(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

static void conf_message(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

static const char *conf_filename;
static int conf_lineno, conf_warnings;

const char conf_defname[] = "arch/$(ARCH)/defconfig";

static void conf_warning(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s:%d:warning: ", conf_filename, conf_lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	conf_warnings++;
}

static void conf_default_message_callback(const char *s)
{
	printf("#\n# ");
	printf("%s", s);
	printf("\n#\n");
}

static void (*conf_message_callback)(const char *s) =
	conf_default_message_callback;
void conf_set_message_callback(void (*fn)(const char *s))
{
	conf_message_callback = fn;
}

static void conf_message(const char *fmt, ...)
{
	va_list ap;
	char buf[4096];

	if (!conf_message_callback)
		return;

	va_start(ap, fmt);

	vsnprintf(buf, sizeof(buf), fmt, ap);
	conf_message_callback(buf);
	va_end(ap);
}

const char *conf_get_configname(void)
{
	char *name = getenv("KCONFIG_CONFIG");

	return name ? name : ".config";
}

char *conf_get_dependency_file_name(const char *prefix)
{
	char *dest;
	const char suffix[] = "_dependency";

	if (!prefix)
		return NULL;

	dest = malloc(strlen(prefix) + strlen(suffix) + 1);
	sprintf(dest, "%s%s", prefix, suffix);
	return dest;
}

static const char *conf_get_autoconfig_name(void)
{
	char *name = getenv("KCONFIG_AUTOCONFIG");

	return name ? name : "include/config/auto.conf";
}

/*
 * func:	获取拓展目录的config文件路径
 * param:	void
 * return:	char *name	编译目录下Makefile文件中
 *				KCONFIG_EXTEND_AUTOCONFIG宏
 *				若无则为"include/config/.extend.config"
 */
static const char *conf_get_extend_autoconfig_name(void)
{
	char *name = getenv("KCONFIG_EXTEND_AUTOCONFIG");

	return name ? name : "include/config/.extend.config";
}

char *conf_get_default_confname(void)
{
	static char fullname[PATH_MAX+1];
	char *env, *name;

	name = expand_string(conf_defname);
	env = getenv(SRCTREE);
	if (env) {
		snprintf(fullname, sizeof(fullname), "%s/%s", env, name);
		if (is_present(fullname))
			return fullname;
	}
	return name;
}

static int conf_set_sym_val(struct symbol *sym, int def, int def_flags, char *p)
{
	char *p2;

	switch (sym->type) {
	case S_TRISTATE:
		if (p[0] == 'm') {
			sym->def[def].tri = mod;
			sym->flags |= def_flags;
			break;
		}
		/* fall through */
	case S_BOOLEAN:
		if (p[0] == 'y') {
			sym->def[def].tri = yes;
			sym->flags |= def_flags;
			break;
		}
		if (p[0] == 'n') {
			sym->def[def].tri = no;
			sym->flags |= def_flags;
			break;
		}
		if (def != S_DEF_AUTO)
			conf_warning("symbol value '%s' invalid for %s",
				     p, sym->name);
		return 1;
	case S_STRING:
		if (*p++ != '"')
			break;
		for (p2 = p; (p2 = strpbrk(p2, "\"\\")); p2++) {
			if (*p2 == '"') {
				*p2 = 0;
				break;
			}
			memmove(p2, p2 + 1, strlen(p2));
		}
		if (!p2) {
			if (def != S_DEF_AUTO)
				conf_warning("invalid string found");
			return 1;
		}
		/* fall through */
	case S_INT:
	case S_HEX:
		if (sym_string_valid(sym, p)) {
			sym->def[def].val = xstrdup(p);
			sym->flags |= def_flags;
		} else {
			if (def != S_DEF_AUTO)
				conf_warning("symbol value '%s' invalid for %s",
					     p, sym->name);
			return 1;
		}
		break;
	default:
		;
	}
	return 0;
}

#define LINE_GROWTH 16
static int add_byte(int c, char **lineptr, size_t slen, size_t *n)
{
	char *nline;
	size_t new_size = slen + 1;
	if (new_size > *n) {
		new_size += LINE_GROWTH - 1;
		new_size *= 2;
		nline = xrealloc(*lineptr, new_size);
		if (!nline)
			return -1;

		*lineptr = nline;
		*n = new_size;
	}

	(*lineptr)[slen] = c;

	return 0;
}

static ssize_t compat_getline(char **lineptr, size_t *n, FILE *stream)
{
	char *line = *lineptr;
	size_t slen = 0;

	for (;;) {
		int c = getc(stream);

		switch (c) {
		case '\n':
			if (add_byte(c, &line, slen, n) < 0)
				goto e_out;
			slen++;
			/* fall through */
		case EOF:
			if (add_byte('\0', &line, slen, n) < 0)
				goto e_out;
			*lineptr = line;
			if (slen == 0)
				return -1;
			return slen;
		default:
			if (add_byte(c, &line, slen, n) < 0)
				goto e_out;
			slen++;
		}
	}

e_out:
	line[slen-1] = '\0';
	*lineptr = line;
	return -1;
}

int conf_read_simple(const char *name, int def)
{
	FILE *in = NULL;
	char   *line = NULL;
	size_t  line_asize = 0;
	char *p, *p2;
	struct symbol *sym;
	int i, def_flags;

	if (name) {
		in = zconf_fopen(name);
	} else {
		struct property *prop;

		name = conf_get_configname();
		in = zconf_fopen(name);
		if (in)
			goto load;
		sym_add_change_count(1);
		if (!sym_defconfig_list)
			return 1;

		for_all_defaults(sym_defconfig_list, prop) {
			if (expr_calc_value(prop->visible.expr) == no ||
			    prop->expr->type != E_SYMBOL)
				continue;
			sym_calc_value(prop->expr->left.sym);
			name = sym_get_string_value(prop->expr->left.sym);
			in = zconf_fopen(name);
			if (in) {
				conf_message("using defaults found in %s",
					 name);
				goto load;
			}
		}
	}
	if (!in)
		return 1;

load:
	conf_filename = name;
	conf_lineno = 0;
	conf_warnings = 0;

	def_flags = SYMBOL_DEF << def;
	for_all_symbols(i, sym) {
		sym->flags |= SYMBOL_CHANGED;
		sym->flags &= ~(def_flags|SYMBOL_VALID);
		if (sym_is_choice(sym))
			sym->flags |= def_flags;
		switch (sym->type) {
		case S_INT:
		case S_HEX:
		case S_STRING:
			if (sym->def[def].val)
				free(sym->def[def].val);
			/* fall through */
		default:
			sym->def[def].val = NULL;
			sym->def[def].tri = no;
		}
	}

	while (compat_getline(&line, &line_asize, in) != -1) {
		conf_lineno++;
		sym = NULL;
		if (line[0] == '#') {
			if (memcmp(line + 2, CONFIG_, strlen(CONFIG_)))
				continue;
			p = strchr(line + 2 + strlen(CONFIG_), ' ');
			if (!p)
				continue;
			*p++ = 0;
			if (strncmp(p, "is not set", 10))
				continue;
			if (def == S_DEF_USER) {
				sym = sym_find(line + 2 + strlen(CONFIG_));
				if (!sym) {
					sym_add_change_count(1);
					continue;
				}
			} else {
				sym = sym_lookup(line + 2 + strlen(CONFIG_), 0);
				if (sym->type == S_UNKNOWN)
					sym->type = S_BOOLEAN;
			}
			if (sym->flags & def_flags) {
				conf_warning("override: reassigning to symbol %s", sym->name);
			}
			switch (sym->type) {
			case S_BOOLEAN:
			case S_TRISTATE:
				sym->def[def].tri = no;
				sym->flags |= def_flags;
				break;
			default:
				;
			}
		} else if (memcmp(line, CONFIG_, strlen(CONFIG_)) == 0) {
			p = strchr(line + strlen(CONFIG_), '=');
			if (!p)
				continue;
			*p++ = 0;
			p2 = strchr(p, '\n');
			if (p2) {
				*p2-- = 0;
				if (*p2 == '\r')
					*p2 = 0;
			}

			sym = sym_find(line + strlen(CONFIG_));
			if (!sym) {
				if (def == S_DEF_AUTO)
					/*
					 * Reading from include/config/auto.conf
					 * If CONFIG_FOO previously existed in
					 * auto.conf but it is missing now,
					 * include/config/foo.h must be touched.
					 */
					conf_touch_dep(line + strlen(CONFIG_));
				else
					sym_add_change_count(1);
				continue;
			}

			if (sym->flags & def_flags) {
				conf_warning("override: reassigning to symbol %s", sym->name);
			}
			if (conf_set_sym_val(sym, def, def_flags, p))
				continue;
		} else {
			if (line[0] != '\r' && line[0] != '\n')
				conf_warning("unexpected data: %.*s",
					     (int)strcspn(line, "\r\n"), line);

			continue;
		}

		if (sym && sym_is_choice_value(sym)) {
			struct symbol *cs = prop_get_symbol(sym_get_choice_prop(sym));
			switch (sym->def[def].tri) {
			case no:
				break;
			case mod:
				if (cs->def[def].tri == yes) {
					conf_warning("%s creates inconsistent choice state", sym->name);
					cs->flags &= ~def_flags;
				}
				break;
			case yes:
				if (cs->def[def].tri != no)
					conf_warning("override: %s changes choice state", sym->name);
				cs->def[def].val = sym;
				break;
			}
			cs->def[def].tri = EXPR_OR(cs->def[def].tri, sym->def[def].tri);
		}
	}
	free(line);
	fclose(in);
	return 0;
}

int conf_read(const char *name)
{
	struct symbol *sym;
	int conf_unsaved = 0;
	int i;

	sym_set_change_count(0);

	if (conf_read_simple(name, S_DEF_USER)) {
		sym_calc_value(modules_sym);
		return 1;
	}

	sym_calc_value(modules_sym);

	for_all_symbols(i, sym) {
		sym_calc_value(sym);
		if (sym_is_choice(sym) || (sym->flags & SYMBOL_NO_WRITE))
			continue;
		if (sym_has_value(sym) && (sym->flags & SYMBOL_WRITE)) {
			/* check that calculated value agrees with saved value */
			switch (sym->type) {
			case S_BOOLEAN:
			case S_TRISTATE:
				if (sym->def[S_DEF_USER].tri != sym_get_tristate_value(sym))
					break;
				if (!sym_is_choice(sym))
					continue;
				/* fall through */
			default:
				if (!strcmp(sym->curr.val, sym->def[S_DEF_USER].val))
					continue;
				break;
			}
		} else if (!sym_has_value(sym) && !(sym->flags & SYMBOL_WRITE))
			/* no previous value and not saved */
			continue;
		conf_unsaved++;
		/* maybe print value in verbose mode... */
	}

	for_all_symbols(i, sym) {
		if (sym_has_value(sym) && !sym_is_choice_value(sym)) {
			/* Reset values of generates values, so they'll appear
			 * as new, if they should become visible, but that
			 * doesn't quite work if the Kconfig and the saved
			 * configuration disagree.
			 */
			if (sym->visible == no && !conf_unsaved)
				sym->flags &= ~SYMBOL_DEF_USER;
			switch (sym->type) {
			case S_STRING:
			case S_INT:
			case S_HEX:
				/* Reset a string value if it's out of range */
				if (sym_string_within_range(sym, sym->def[S_DEF_USER].val))
					break;
				sym->flags &= ~(SYMBOL_VALID|SYMBOL_DEF_USER);
				conf_unsaved++;
				break;
			default:
				break;
			}
		}
	}

	sym_add_change_count(conf_warnings || conf_unsaved);

	return 0;
}

/*
 * Kconfig configuration printer
 *
 * This printer is used when generating the resulting configuration after
 * kconfig invocation and `defconfig' files. Unset symbol might be omitted by
 * passing a non-NULL argument to the printer.
 *
 */
static void
kconfig_print_symbol(FILE *fp, struct symbol *sym, const char *value, void *arg)
{

	switch (sym->type) {
	case S_BOOLEAN:
	case S_TRISTATE:
		if (*value == 'n') {
			bool skip_unset = (arg != NULL);

			if (!skip_unset)
				fprintf(fp, "# %s%s is not set\n",
				    CONFIG_, sym->name);
			return;
		}
		break;
	default:
		break;
	}

	fprintf(fp, "%s%s=%s\n", CONFIG_, sym->name, value);
}

static void
kconfig_print_comment(FILE *fp, const char *value, void *arg)
{
	const char *p = value;
	size_t l;

	for (;;) {
		l = strcspn(p, "\n");
		fprintf(fp, "#");
		if (l) {
			fprintf(fp, " ");
			xfwrite(p, l, 1, fp);
			p += l;
		}
		fprintf(fp, "\n");
		if (*p++ == '\0')
			break;
	}
}

static struct conf_printer kconfig_printer_cb =
{
	.print_symbol = kconfig_print_symbol,
	.print_comment = kconfig_print_comment,
};

/*
 * Header printer
 *
 * This printer is used when generating the `include/generated/autoconf.h' file.
 */
static void
header_print_symbol(FILE *fp, struct symbol *sym, const char *value, void *arg)
{

	switch (sym->type) {
	case S_BOOLEAN:
	case S_TRISTATE: {
		const char *suffix = "";

		switch (*value) {
		case 'n':
			break;
		case 'm':
			suffix = "_MODULE";
			/* fall through */
		default:
			fprintf(fp, "#define %s%s%s 1\n",
			    CONFIG_, sym->name, suffix);
		}
		break;
	}
	case S_HEX: {
		const char *prefix = "";

		if (value[0] != '0' || (value[1] != 'x' && value[1] != 'X'))
			prefix = "0x";
		fprintf(fp, "#define %s%s %s%s\n",
		    CONFIG_, sym->name, prefix, value);
		break;
	}
	case S_STRING:
	case S_INT:
		fprintf(fp, "#define %s%s %s\n",
		    CONFIG_, sym->name, value);
		break;
	default:
		break;
	}

}

/*
 * func:	在自动生成的头文件中写入时间宏
 * param:	FILE *fp				写入的文件指针
 *		const char *m_timestamp_format_c	模版中time宏名
 * return:	void
 */
static void
header_print_time(FILE *fp, const char *m_timestamp_format_c)
{
	time_t now;
	struct tm *build_time;
	size_t ret;

	time(&now);
	build_time = localtime(&now);

	char buf[strlen(m_timestamp_format_c) +
		 sizeof("\"YYYY-MM-DD HH:MM:SS \"\n") + TIMEZONE_LEN];

	ret = strftime(buf, sizeof(buf), "\"%Y-%m-%d %H:%M:%S %Z\"\n",
		       build_time);

	if (ret == 0)
		strftime(buf, sizeof(buf), "\"%Y-%m-%d %H:%M:%S\"\n",
			 build_time);
	fprintf(fp, m_timestamp_format_c, buf);
}

static void
header_print_comment(FILE *fp, const char *value, void *arg)
{
	const char *p = value;
	size_t l;

	fprintf(fp, "/*\n");
	for (;;) {
		l = strcspn(p, "\n");
		fprintf(fp, " *");
		if (l) {
			fprintf(fp, " ");
			xfwrite(p, l, 1, fp);
			p += l;
		}
		fprintf(fp, "\n");
		if (*p++ == '\0')
			break;
	}
	fprintf(fp, " */\n");
}

/*
 * func:	写入自动生成头文件的注释格式
 * param:	FILE *fp		需要写入的文件指针
 *		const char *value	注释内容
 *		void *arg		模板结构体指针
 * return:	void
 */
static void
extend_header_print_comment(FILE *fp, const char *value, void *arg)
{
	header_print_comment(fp, value, NULL);

	/* 在拓展目录侧生成配置文件时添加时间宏 */
	const char *extend_dep = getenv("KCONFIG_EXTEND_CONFIG_ENABLE");

	/* 判断拓展模块是否需额外生成头文件 */
	/* 判断模板中是否有time段 */
	if (extend_dep && (strcmp(extend_dep, "y") == 0) &&
	    (((struct template *)arg)->m_timestamp_offset_c != -1))
		/* 在头文件第一行定义时间宏 */
		header_print_time(fp, ((struct template *)arg)->data +
			((struct template *)arg)->m_timestamp_offset_c);
}

/*
 * func:	在拓展目录下的自动生成头文件中写入配置内容:
 *		过滤unikraft配置
 *		生成对应的宏定义逻辑
 * param:	FILE *fp		自动生成头文件指针
 *		struct symbol *sym	指向config结束生成的哈希表
 *		const char *value	具体配置项的值'Y'("CONFIG_XXX=Y")
 *		void *arg		模板结构体指针
 * return:	void
 */
static void
extend_header_print_symbol(FILE *fp, struct symbol *sym,
			   const char *value, void *arg)
{
	const char *suffix = "";
	const char *prefix = "";
	const char *temp_val = "";

	/* 处理 CONFIG_XXX=n 场景 */
	if (((sym->type == S_BOOLEAN) || (sym->type == S_TRISTATE)) &&
	    (*value == 'n')) {
		/* 判断模板中是否有unset段,有则输出模板内容 */
		if (((struct template *)arg)->m_unset_offset_s != -1)
			fprintf(fp, ((struct template *)arg)->data +
				((struct template *)arg)->m_unset_offset_s,
				sym->name);
		return;
	}

	/* 处理 CONFIG_XXX=y / CONFIG_XXX=<value> 场景 */
	/* 根据不同变量类型与变量的值作不同的转换 */
	switch (sym->type) {
	/* 处理只有y/n逻辑的配置，简单输出1/0即可 */
	case S_BOOLEAN:
	case S_TRISTATE:
		switch (*value) {
		case 'm':
			suffix = "_MODULE";
		default:
			/* 选项类型为bool,则CONFIG宏值为1 */
			/* 输出#define CONFIG_XXX 1*/
			temp_val = "1";
			break;
		}
		break;
	/* 值如果为十六进制,值前缀加"=0x" */
	case S_HEX:
		if (value[0] != '0' || (value[1] != 'x' && value[1] != 'X'))
			prefix = "0x";
		temp_val = (char *)value;
		break;
	/* 值如果为字符串或者整型,使用value即可 */
	case S_STRING:
	case S_INT:
		temp_val = (char *)value;
		break;
	default:
		break;
	}
	/* 无论模板如何,拓展目录下都会输出一行默认宏 */
	/* #define CONFIG_XXX <value> */
	fprintf(fp, "#define CONFIG_%s%s %s%s\n", sym->name, suffix,
		prefix, temp_val);
	/* 向app头文件中输出模板内容 */
	/* 判断模板中是否有set段 */
	if (((struct template *)arg)->m_set_offset_s != -1)
		fprintf(fp, (const char *)((struct template *)arg)->data +
			((struct template *)arg)->m_set_offset_s, sym->name);
}

static struct conf_printer header_printer_cb =
{
	.print_symbol = header_print_symbol,
	.print_comment = header_print_comment,
};

/*
 * 给拓展目录下自动生成头文件写入配置的函数表
 * extend_header_print_symbol写入配置内容
 * extend_header_print_symbol写入注释
 */
static struct conf_printer extend_header_printer_cb = {
	.print_symbol = extend_header_print_symbol,
	.print_comment = extend_header_print_comment,
};

/*
 * Tristate printer
 *
 * This printer is used when generating the `include/config/tristate.conf' file.
 */
static void
tristate_print_symbol(FILE *fp, struct symbol *sym, const char *value, void *arg)
{

	if (sym->type == S_TRISTATE && *value != 'n')
		fprintf(fp, "%s%s=%c\n", CONFIG_, sym->name, (char)toupper(*value));
}

static struct conf_printer tristate_printer_cb =
{
	.print_symbol = tristate_print_symbol,
	.print_comment = kconfig_print_comment,
};

static void conf_write_symbol(FILE *fp, struct symbol *sym,
			      struct conf_printer *printer, void *printer_arg)
{
	const char *str;

	switch (sym->type) {
	case S_UNKNOWN:
		break;
	case S_STRING:
		str = sym_get_string_value(sym);
		str = sym_escape_string_value(str);
		printer->print_symbol(fp, sym, str, printer_arg);
		free((void *)str);
		break;
	default:
		str = sym_get_string_value(sym);
		printer->print_symbol(fp, sym, str, printer_arg);
	}
}

static void
conf_write_heading(FILE *fp, struct conf_printer *printer, void *printer_arg)
{
	char buf[256];

	snprintf(buf, sizeof(buf),
	    "\n"
	    "Automatically generated file; DO NOT EDIT.\n"
	    "%s\n",
	    rootmenu.prompt->text);

	printer->print_comment(fp, buf, printer_arg);
}

/*
 * Write out a minimal config.
 * All values that has default values are skipped as this is redundant.
 */
int conf_write_defconfig(const char *filename)
{
	struct symbol *sym;
	struct menu *menu;
	FILE *out;

	out = fopen(filename, "w");
	if (!out)
		return 1;

	sym_clear_all_valid();

	/* Traverse all menus to find all relevant symbols */
	menu = rootmenu.list;

	while (menu != NULL)
	{
		sym = menu->sym;
		if (sym == NULL) {
			if (!menu_is_visible(menu))
				goto next_menu;
		} else if (!sym_is_choice(sym)) {
			sym_calc_value(sym);
			if (!(sym->flags & SYMBOL_WRITE))
				goto next_menu;
			sym->flags &= ~SYMBOL_WRITE;
			/* If we cannot change the symbol - skip */
			if (!sym_is_changable(sym))
				goto next_menu;
			/* If symbol equals to default value - skip */
			if (strcmp(sym_get_string_value(sym), sym_get_string_default(sym)) == 0)
				goto next_menu;

			/*
			 * If symbol is a choice value and equals to the
			 * default for a choice - skip.
			 * But only if value is bool and equal to "y" and
			 * choice is not "optional".
			 * (If choice is "optional" then all values can be "n")
			 */
			if (sym_is_choice_value(sym)) {
				struct symbol *cs;
				struct symbol *ds;

				cs = prop_get_symbol(sym_get_choice_prop(sym));
				ds = sym_choice_default(cs);
				if (!sym_is_optional(cs) && sym == ds) {
					if ((sym->type == S_BOOLEAN) &&
					    sym_get_tristate_value(sym) == yes)
						goto next_menu;
				}
			}
			conf_write_symbol(out, sym, &kconfig_printer_cb, NULL);
		}
next_menu:
		if (menu->list != NULL) {
			menu = menu->list;
		}
		else if (menu->next != NULL) {
			menu = menu->next;
		} else {
			while ((menu = menu->parent)) {
				if (menu->next != NULL) {
					menu = menu->next;
					break;
				}
			}
		}
	}
	fclose(out);
	return 0;
}

int conf_write(const char *name)
{
	FILE *out;
	struct symbol *sym;
	struct menu *menu;
	const char *str;
	char tmpname[PATH_MAX + 1], oldname[PATH_MAX + 1];
	char *env;
	bool need_newline = false;

	if (!name)
		name = conf_get_configname();

	if (!*name) {
		fprintf(stderr, "config name is empty\n");
		return -1;
	}

	if (is_dir(name)) {
		fprintf(stderr, "%s: Is a directory\n", name);
		return -1;
	}

	if (make_parent_dir(name))
		return -1;

	env = getenv("KCONFIG_OVERWRITECONFIG");
	if (env && *env) {
		*tmpname = 0;
		out = fopen(name, "w");
	} else {
		snprintf(tmpname, sizeof(tmpname), "%s.%d.tmp",
			 name, (int)getpid());
		out = fopen(tmpname, "w");
	}
	if (!out)
		return 1;

	conf_write_heading(out, &kconfig_printer_cb, NULL);

	if (!conf_get_changed())
		sym_clear_all_valid();

	menu = rootmenu.list;
	while (menu) {
		sym = menu->sym;
		if (!sym) {
			if (!menu_is_visible(menu))
				goto next;
			str = menu_get_prompt(menu);
			fprintf(out, "\n"
				     "#\n"
				     "# %s\n"
				     "#\n", str);
			need_newline = false;
		} else if (!(sym->flags & SYMBOL_CHOICE)) {
			sym_calc_value(sym);
			if (!(sym->flags & SYMBOL_WRITE))
				goto next;
			if (need_newline) {
				fprintf(out, "\n");
				need_newline = false;
			}
			sym->flags &= ~SYMBOL_WRITE;
			conf_write_symbol(out, sym, &kconfig_printer_cb, NULL);
		}
next:
		if (menu->list) {
			menu = menu->list;
			continue;
		}
		if (menu->next)
			menu = menu->next;
		else while ((menu = menu->parent)) {
			if (!menu->sym && menu_is_visible(menu) &&
			    menu != &rootmenu) {
				str = menu_get_prompt(menu);
				fprintf(out, "# end of %s\n", str);
				need_newline = true;
			}
			if (menu->next) {
				menu = menu->next;
				break;
			}
		}
	}
	fclose(out);

	if (*tmpname) {
		if (is_same(name, tmpname)) {
			conf_message("No change to %s", name);
			unlink(tmpname);
			sym_set_change_count(0);
			return 0;
		}

		snprintf(oldname, sizeof(oldname), "%s.old", name);
		rename(name, oldname);
		if (rename(tmpname, name))
			return 1;
	}

	conf_message("configuration written to %s", name);

	sym_set_change_count(0);

	return 0;
}

/* write a dependency file as used by kbuild to track dependencies */
static int conf_write_dep(const char *name)
{
	struct file *file;
	FILE *out;

	out = fopen("..config.tmp", "w");
	if (!out)
		return 1;
	fprintf(out, "deps_config := \\\n");
	for (file = file_list; file; file = file->next) {
		if (file->next)
			fprintf(out, "\t%s \\\n", file->name);
		else
			fprintf(out, "\t%s\n", file->name);
	}
	fprintf(out, "\n%s: \\\n"
		     "\t$(deps_config)\n\n", conf_get_autoconfig_name());

	env_write_dep(out, conf_get_autoconfig_name());

	fprintf(out, "\n$(deps_config): ;\n");
	fclose(out);

	if (make_parent_dir(name))
		return 1;
	rename("..config.tmp", name);
	return 0;
}

static int conf_touch_deps(void)
{
	const char *name;
	struct symbol *sym;
	int res, i;

	strcpy(depfile_path, "include/config/");
	depfile_prefix_len = strlen(depfile_path);

	name = conf_get_autoconfig_name();
	conf_read_simple(name, S_DEF_AUTO);
	sym_calc_value(modules_sym);

	for_all_symbols(i, sym) {
		sym_calc_value(sym);
		if ((sym->flags & SYMBOL_NO_WRITE) || !sym->name)
			continue;
		if (sym->flags & SYMBOL_WRITE) {
			if (sym->flags & SYMBOL_DEF_AUTO) {
				/*
				 * symbol has old and new value,
				 * so compare them...
				 */
				switch (sym->type) {
				case S_BOOLEAN:
				case S_TRISTATE:
					if (sym_get_tristate_value(sym) ==
					    sym->def[S_DEF_AUTO].tri)
						continue;
					break;
				case S_STRING:
				case S_HEX:
				case S_INT:
					if (!strcmp(sym_get_string_value(sym),
						    sym->def[S_DEF_AUTO].val))
						continue;
					break;
				default:
					break;
				}
			} else {
				/*
				 * If there is no old value, only 'no' (unset)
				 * is allowed as new value.
				 */
				switch (sym->type) {
				case S_BOOLEAN:
				case S_TRISTATE:
					if (sym_get_tristate_value(sym) == no)
						continue;
					break;
				default:
					break;
				}
			}
		} else if (!(sym->flags & SYMBOL_DEF_AUTO))
			/* There is neither an old nor a new value. */
			continue;
		/* else
		 *	There is an old value, but no new value ('no' (unset)
		 *	isn't saved in auto.conf, so the old value is always
		 *	different from 'no').
		 */

		res = conf_touch_dep(sym->name);
		if (res)
			return res;
	}

	return 0;
}

/*
 * func:	判断模板中单行文本是否为标识符
 * param:	char *data			需判断的单行文本
 * return:	enum TEMPLATE_MODE_IDENTIFIER	目前文件读取的状态
 */
static inline int get_template_identifier(char *data)
{
	if (strcmp(data, "<timestamp_c>\n") == 0)
		return MODULE_IDENTIFIER_TIMESTAMP;
	else if (strcmp(data, "<end_timestamp_c>\n") == 0)
		return MODULE_IDENTIFIER_TIMESTAMP_END;
	else if (strcmp(data, "<set_s>\n") == 0)
		return MODULE_IDENTIFIER_SET;
	else if (strcmp(data, "<end_set_s>\n") == 0)
		return MODULE_IDENTIFIER_SET_END;
	else if (strcmp(data, "<unset_s>\n") == 0)
		return MODULE_IDENTIFIER_UNSET;
	else if (strcmp(data, "<end_unset_s>\n") == 0)
		return MODULE_IDENTIFIER_UNSET_END;
	return RAW_DATA;
}

/*
 * func:	app的头文件模板数据初始化
 *		读取模板数据并放入结构体template_data中
 * param:	FILE *fp			模板文件
 *		struct template *template_data	模板数据结构体指针
 * return:	0	成功
 *		1	错误-文件不存在或者格式不符合要求
 *			文件格式(模块顺序不影响读取)：
 *			<timestamp_c>
 *			...
 *			<end_timestamp_c>
 *			<set_s>
 *			...
 *			<end_set_s>
 *			<unset_s>
 *			...
 *			<end_unset_s>
 */
static int
extend_template_init(FILE *fp, struct template *template_data)
{
	char line[EXTEND_TEMPLATE_FILE_LEN];
	int length;
	/* in_module标识此模块是否处理完毕 */
	int in_module = 0;
	/* offset存储已经处理的有效数据长度 */
	int offset = 0;
	/* prev_identifier标识上一个处理的模块 */
	enum TEMPLATE_MODE_IDENTIFIER prev_identifier = RAW_DATA;
	enum TEMPLATE_MODE_IDENTIFIER mode;

	/* 解析模板文件 */
	while (fgets(line, EXTEND_TEMPLATE_FILE_LEN, fp)) {
		length = strlen(line);
		mode = get_template_identifier(line);
		switch (mode) {
		case MODULE_IDENTIFIER_TIMESTAMP:
			if ((in_module != 0) ||
			    (template_data->m_timestamp_offset_c != -1))
				return 1;
			in_module = 1;
			prev_identifier = MODULE_IDENTIFIER_TIMESTAMP;
			template_data->m_timestamp_offset_c = offset;
			break;
		case MODULE_IDENTIFIER_TIMESTAMP_END:
			if ((in_module == 0) ||
			    (prev_identifier != MODULE_IDENTIFIER_TIMESTAMP))
				return 1;
			in_module = 0;
			*(template_data->data + offset) = '\0';
			offset++;
			break;
		case MODULE_IDENTIFIER_SET:
			if ((in_module != 0) ||
			    (template_data->m_set_offset_s != -1))
				return 1;
			in_module = 1;
			prev_identifier = MODULE_IDENTIFIER_SET;
			template_data->m_set_offset_s = offset;
			break;
		case MODULE_IDENTIFIER_SET_END:
			if ((in_module == 0) ||
			    (prev_identifier != MODULE_IDENTIFIER_SET))
				return 1;
			in_module = 0;
			*(template_data->data + offset) = '\0';
			offset++;
			break;
		case MODULE_IDENTIFIER_UNSET:
			if ((in_module != 0) ||
			    (template_data->m_unset_offset_s != -1))
				return 1;
			in_module = 1;
			prev_identifier = MODULE_IDENTIFIER_UNSET;
			template_data->m_unset_offset_s = offset;
			break;
		case MODULE_IDENTIFIER_UNSET_END:
			if ((in_module == 0) ||
			    (prev_identifier != MODULE_IDENTIFIER_UNSET))
				return 1;
			in_module = 0;
			*(template_data->data + offset) = '\0';
			offset++;
			break;
		default:
			if (in_module != 0) {
				if (offset > EXTEND_TEMPLATE_FILE_MAX) {
					/* 文件大小超512bytes报错 */
					return 1;
				}
				memcpy(template_data->data + offset, line,
				       length);
				offset += length;
			}
			break;
		}
	}

	if (in_module != 0) {
		fprintf(stderr,
			"\ntemplate file misses termination identifier or\n"
			"The last bit of the file is not a enter\n");
		return 1;
	}
	return 0;
}

/*
 * func:	创建并根据配置项更新:unikraft下的config文件
 *				   自动生成的头文件
 *				   tristate.config文件
 *				   (可选)拓展目录下的config文件
 * param:	int overwrite	本次操作是否为覆写
 * return:	0-成功
 *		1-失败
 */
int conf_write_autoconf(int overwrite)
{
	struct symbol *sym;
	const char *name;
	const char *autoconf_name = conf_get_autoconfig_name();
	const char *extend_autoconf_name = conf_get_extend_autoconfig_name();
	FILE *out, *tristate, *out_h, *out_extend_h, *out_extend;
	FILE *template_fp;
	struct template *template_data;
	const char *extend_name, *extend_dep, *extend_template_name;
	int i, extend_enable;

	/* KCONFIG_EXTEND_CONFIG_ENABLE=y则向拓展目录输出配置文件 */
	extend_dep = getenv("KCONFIG_EXTEND_CONFIG_ENABLE");
	if ((extend_dep) && (strcmp(extend_dep, "y") == 0)) {
		extend_template_name = getenv("KCONFIG_EXTEND_TEMPLATE");
		extend_enable = 1;
		extend_name = getenv("KCONFIG_EXTEND_NAME");
		if (extend_name == NULL) {
			fprintf(stderr,
				"\nError while getting extend name.\n"
				"Please define KCONFIG_EXTEND_NAME\n");
			return 1;
		}
	} else
		extend_enable = 0;

	if (!overwrite && is_present(autoconf_name))
		return 0;

	sym_clear_all_valid();

	conf_write_dep("include/config/auto.conf.cmd");

	if (conf_touch_deps())
		return 1;

	out = fopen(".tmpconfig", "w");
	if (!out)
		return 1;

	tristate = fopen(".tmpconfig_tristate", "w");
	if (!tristate) {
		fclose(out);
		return 1;
	}

	out_h = fopen(".tmpconfig.h", "w");
	if (!out_h) {
		fclose(out);
		fclose(tristate);
		return 1;
	}

	if (extend_enable) {
		/* 给模板数据申请固定buffer */
		template_data = (struct template *)
					malloc(sizeof(template_data));
		template_data->data = (char *)malloc(EXTEND_TEMPLATE_FILE_MAX);
		/* 初始化模板数据偏移 */
		template_data->m_timestamp_offset_c = -1;
		template_data->m_set_offset_s = -1;
		template_data->m_unset_offset_s = -1;
		if (extend_template_name) {
			template_fp = fopen(extend_template_name, "rb");
			if (!template_fp) {
				/* 不存在模板文件报错 */
				fprintf(stderr,
					"\nError while opening template file.\n"
					"Please check your template file path\n");
				goto err_handle_extend_file;
			} else if (extend_template_init(template_fp,
				   template_data)) {
				/* extend_template_init */
				/* 初始化模板数据template_data */
				fprintf(stderr,
					"\nError while initializing template file.\n"
					"Please check that the contents of your file conform to the format\n"
					"and file size is less than 512 bytes\n");
				fclose(template_fp);
				goto err_handle_extend_file;
			}
			fclose(template_fp);
		}
		out_extend_h = fopen(".extend.tmpconfig.h", "w");
		if (!out_extend_h) {
			fprintf(stderr,
				"\nError while creating auto-config head file.\n");
			goto err_handle_extend_file;
		}
		out_extend = fopen(".extend.tmpconfig", "w");
		if (!out_extend) {
			fprintf(stderr,
				"\nError while creating auto-config config file.\n");
			fclose(out_extend_h);
			goto err_handle_extend_file;
		}
		conf_write_heading(out_extend_h, &extend_header_printer_cb,
				   (void *)template_data);
		conf_write_heading(out_extend, &kconfig_printer_cb, NULL);
	}

	conf_write_heading(out, &kconfig_printer_cb, NULL);

	conf_write_heading(tristate, &tristate_printer_cb, NULL);

	conf_write_heading(out_h, &header_printer_cb, NULL);

	for_all_symbols(i, sym) {
		sym_calc_value(sym);
		if (!(sym->flags & SYMBOL_WRITE) || !sym->name)
			continue;

		/* write symbol to auto.conf, tristate and header files */
		conf_write_symbol(out, sym, &kconfig_printer_cb, (void *)1);

		conf_write_symbol(tristate, sym, &tristate_printer_cb, (void *)1);

		conf_write_symbol(out_h, sym, &header_printer_cb, NULL);

		if (extend_enable) {
			if (strstr(sym->name, extend_name)) {
				/* 右移sys->name，去除名称 */
				sym->name += (strlen(extend_name) + 1);
				conf_write_symbol(out_extend_h, sym,
						  &extend_header_printer_cb,
						  (void *)template_data);
				conf_write_symbol(out_extend, sym,
						  &kconfig_printer_cb,
						  NULL);
				/* 还原sys->name，不影响后续使用 */
				sym->name -= (strlen(extend_name) + 1);
			}
		}
	}

	fclose(out);
	fclose(tristate);
	fclose(out_h);
	if (extend_enable) {
		/* 释放模板buffer */
		free(template_data->data);
		free(template_data);
		fclose(out_extend_h);
		fclose(out_extend);

		name = getenv("KCONFIG_EXTEND_AUTOHEADER");
		if (!name)
			name = "include/config/extend_autoconf.h";
		if (make_parent_dir(name))
			return 1;
		if (rename(".extend.tmpconfig.h", name))
			return 1;
		if (make_parent_dir(extend_autoconf_name))
			return 1;
		if (rename(".extend.tmpconfig", extend_autoconf_name))
			return 1;
	}

	name = getenv("KCONFIG_AUTOHEADER");
	if (!name)
		name = "include/generated/autoconf.h";
	if (make_parent_dir(name))
		return 1;
	if (rename(".tmpconfig.h", name))
		return 1;

	name = getenv("KCONFIG_TRISTATE");
	if (!name)
		name = "include/config/tristate.conf";
	if (make_parent_dir(name))
		return 1;
	if (rename(".tmpconfig_tristate", name))
		return 1;

	if (make_parent_dir(autoconf_name))
		return 1;
	/*
	 * This must be the last step, kbuild has a dependency on auto.conf
	 * and this marks the successful completion of the previous steps.
	 */
	if (rename(".tmpconfig", autoconf_name))
		return 1;

	return 0;

	/* extend功能异常处理入口 */
err_handle_extend_file:
	free(template_data->data);
	free(template_data);
	fclose(out_h);
	fclose(tristate);
	fclose(out);
	return 1;
}

static int sym_change_count;
static void (*conf_changed_callback)(void);

void sym_set_change_count(int count)
{
	int _sym_change_count = sym_change_count;
	sym_change_count = count;
	if (conf_changed_callback &&
	    (bool)_sym_change_count != (bool)count)
		conf_changed_callback();
}

void sym_add_change_count(int count)
{
	sym_set_change_count(count + sym_change_count);
}

bool conf_get_changed(void)
{
	return sym_change_count;
}

void conf_set_changed_callback(void (*fn)(void))
{
	conf_changed_callback = fn;
}

static bool randomize_choice_values(struct symbol *csym)
{
	struct property *prop;
	struct symbol *sym;
	struct expr *e;
	int cnt, def;

	/*
	 * If choice is mod then we may have more items selected
	 * and if no then no-one.
	 * In both cases stop.
	 */
	if (csym->curr.tri != yes)
		return false;

	prop = sym_get_choice_prop(csym);

	/* count entries in choice block */
	cnt = 0;
	expr_list_for_each_sym(prop->expr, e, sym)
		cnt++;

	/*
	 * find a random value and set it to yes,
	 * set the rest to no so we have only one set
	 */
	def = (rand() % cnt);

	cnt = 0;
	expr_list_for_each_sym(prop->expr, e, sym) {
		if (def == cnt++) {
			sym->def[S_DEF_USER].tri = yes;
			csym->def[S_DEF_USER].val = sym;
		}
		else {
			sym->def[S_DEF_USER].tri = no;
		}
		sym->flags |= SYMBOL_DEF_USER;
		/* clear VALID to get value calculated */
		sym->flags &= ~SYMBOL_VALID;
	}
	csym->flags |= SYMBOL_DEF_USER;
	/* clear VALID to get value calculated */
	csym->flags &= ~(SYMBOL_VALID);

	return true;
}

void set_all_choice_values(struct symbol *csym)
{
	struct property *prop;
	struct symbol *sym;
	struct expr *e;

	prop = sym_get_choice_prop(csym);

	/*
	 * Set all non-assinged choice values to no
	 */
	expr_list_for_each_sym(prop->expr, e, sym) {
		if (!sym_has_value(sym))
			sym->def[S_DEF_USER].tri = no;
	}
	csym->flags |= SYMBOL_DEF_USER;
	/* clear VALID to get value calculated */
	csym->flags &= ~(SYMBOL_VALID | SYMBOL_NEED_SET_CHOICE_VALUES);
}

bool conf_set_all_new_symbols(enum conf_def_mode mode)
{
	struct symbol *sym, *csym;
	int i, cnt, pby, pty, ptm;	/* pby: probability of bool     = y
					 * pty: probability of tristate = y
					 * ptm: probability of tristate = m
					 */

	pby = 50; pty = ptm = 33; /* can't go as the default in switch-case
				   * below, otherwise gcc whines about
				   * -Wmaybe-uninitialized */
	if (mode == def_random) {
		int n, p[3];
		char *env = getenv("KCONFIG_PROBABILITY");
		n = 0;
		while( env && *env ) {
			char *endp;
			int tmp = strtol( env, &endp, 10 );
			if( tmp >= 0 && tmp <= 100 ) {
				p[n++] = tmp;
			} else {
				errno = ERANGE;
				perror( "KCONFIG_PROBABILITY" );
				exit( 1 );
			}
			env = (*endp == ':') ? endp+1 : endp;
			if( n >=3 ) {
				break;
			}
		}
		switch( n ) {
		case 1:
			pby = p[0]; ptm = pby/2; pty = pby-ptm;
			break;
		case 2:
			pty = p[0]; ptm = p[1]; pby = pty + ptm;
			break;
		case 3:
			pby = p[0]; pty = p[1]; ptm = p[2];
			break;
		}

		if( pty+ptm > 100 ) {
			errno = ERANGE;
			perror( "KCONFIG_PROBABILITY" );
			exit( 1 );
		}
	}
	bool has_changed = false;

	for_all_symbols(i, sym) {
		if (sym_has_value(sym) || (sym->flags & SYMBOL_VALID))
			continue;
		switch (sym_get_type(sym)) {
		case S_BOOLEAN:
		case S_TRISTATE:
			has_changed = true;
			switch (mode) {
			case def_yes:
				sym->def[S_DEF_USER].tri = yes;
				break;
			case def_mod:
				sym->def[S_DEF_USER].tri = mod;
				break;
			case def_no:
				if (sym->flags & SYMBOL_ALLNOCONFIG_Y)
					sym->def[S_DEF_USER].tri = yes;
				else
					sym->def[S_DEF_USER].tri = no;
				break;
			case def_random:
				sym->def[S_DEF_USER].tri = no;
				cnt = rand() % 100;
				if (sym->type == S_TRISTATE) {
					if (cnt < pty)
						sym->def[S_DEF_USER].tri = yes;
					else if (cnt < (pty+ptm))
						sym->def[S_DEF_USER].tri = mod;
				} else if (cnt < pby)
					sym->def[S_DEF_USER].tri = yes;
				break;
			default:
				continue;
			}
			if (!(sym_is_choice(sym) && mode == def_random))
				sym->flags |= SYMBOL_DEF_USER;
			break;
		default:
			break;
		}

	}

	sym_clear_all_valid();

	/*
	 * We have different type of choice blocks.
	 * If curr.tri equals to mod then we can select several
	 * choice symbols in one block.
	 * In this case we do nothing.
	 * If curr.tri equals yes then only one symbol can be
	 * selected in a choice block and we set it to yes,
	 * and the rest to no.
	 */
	if (mode != def_random) {
		for_all_symbols(i, csym) {
			if ((sym_is_choice(csym) && !sym_has_value(csym)) ||
			    sym_is_choice_value(csym))
				csym->flags |= SYMBOL_NEED_SET_CHOICE_VALUES;
		}
	}

	for_all_symbols(i, csym) {
		if (sym_has_value(csym) || !sym_is_choice(csym))
			continue;

		sym_calc_value(csym);
		if (mode == def_random)
			has_changed = randomize_choice_values(csym);
		else {
			set_all_choice_values(csym);
			has_changed = true;
		}
	}

	return has_changed;
}
