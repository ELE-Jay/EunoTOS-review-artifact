/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2002 Roman Zippel <zippel@linux-m68k.org>
 */

#ifndef LKC_H
#define LKC_H

#include "expr.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "lkc_proto.h"

#define SRCTREE "srctree"

#ifndef PACKAGE
#define PACKAGE "linux"
#endif

#ifndef CONFIG_
#define CONFIG_ "CONFIG_"
#endif
static inline const char *CONFIG_prefix(void)
{
	return getenv( "CONFIG_" ) ?: CONFIG_;
}
#undef CONFIG_
#define CONFIG_ CONFIG_prefix()

enum conf_def_mode {
	def_default,
	def_yes,
	def_mod,
	def_no,
	def_random
};

extern int yylineno;
void zconfdump(FILE *out);
void zconf_starthelp(void);
FILE *zconf_fopen(const char *name);
void zconf_initscan(const char *name);
void zconf_nextfile(const char *name);
void zconf_nextfiles(const char *name);
int zconf_lineno(void);
const char *zconf_curname(void);

/* confdata.c */
/* 拓展模板文件大小限制(byte) */
#define EXTEND_TEMPLATE_FILE_MAX 512
/* 拓展模板文件单行读取缓存长度 */
#define EXTEND_TEMPLATE_FILE_LEN 80
/* c库strftime输出附加空间大小(byte) */
#define TIMEZONE_LEN 13
/*
 * TEMPLATE_MODE_IDENTIFIER为模板内容标识符
 * 拓展模板内容分为三部分:timestamp、set、unset
 * timestamp，存储时间宏
 * set/unset，存储配置模板内容
 */
enum TEMPLATE_MODE_IDENTIFIER {
	RAW_DATA,
	MODULE_IDENTIFIER_TIMESTAMP,
	MODULE_IDENTIFIER_TIMESTAMP_END,
	MODULE_IDENTIFIER_SET,
	MODULE_IDENTIFIER_SET_END,
	MODULE_IDENTIFIER_UNSET,
	MODULE_IDENTIFIER_UNSET_END
};
/*
 * 拓展模板结构体template
 * XXX_c为comment阶段调用(每个头文件只调用一次)
 * XXX_s为symbol阶段调用(每行config调用一次)
 * char *data			存储模板数据buffer
 * int m_timestamp_offset_c	模板数据time宏名的偏移
 *				timestamp为时间宏名称
 * int m_set_offset_s		模板数据set内容的偏移
 *				set为自动生成头文件中
 *				需要配置选项的宏定义格式
 * int m_unset_offset_s		模板数据unset内容的偏移
 *				unset为自动生成头文件中
 *				不需要配置选项的宏定义格式
 */
struct template {
	char *data;
	int m_timestamp_offset_c;
	int m_set_offset_s;
	int m_unset_offset_s;
};
const char *conf_get_configname(void);
char *conf_get_dependency_file_name(const char *prefix);
char *conf_get_default_confname(void);
void sym_set_change_count(int count);
void sym_add_change_count(int count);
bool conf_set_all_new_symbols(enum conf_def_mode mode);
void set_all_choice_values(struct symbol *csym);

/* confdata.c and expr.c */
static inline void xfwrite(const void *str, size_t len, size_t count, FILE *out)
{
	assert(len != 0);

	if (fwrite(str, len, count, out) != count)
		fprintf(stderr, "Error in writing or end of file.\n");
}

/* menu.c */
void _menu_init(void);
void menu_warn(struct menu *menu, const char *fmt, ...);
struct menu *menu_add_menu(void);
void menu_end_menu(void);
void menu_add_entry(struct symbol *sym);
void menu_add_dep(struct expr *dep);
void menu_add_visibility(struct expr *dep);
struct property *menu_add_prompt(enum prop_type type, char *prompt, struct expr *dep);
void menu_add_expr(enum prop_type type, struct expr *expr, struct expr *dep);
void menu_add_symbol(enum prop_type type, struct symbol *sym, struct expr *dep);
void menu_add_option_modules(void);
void menu_add_option_defconfig_list(void);
void menu_add_option_allnoconfig_y(void);
void menu_finalize(struct menu *parent);
void menu_set_type(int type);

/* util.c */
struct file *file_lookup(const char *name, bool create);
void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *p, size_t size);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);
bool xstrcontains(const char *s, const char *c);

/* lexer.l */
int yylex(void);

struct gstr {
	size_t len;
	char  *s;
	/*
	* when max_width is not zero long lines in string s (if any) get
	* wrapped not to exceed the max_width value
	*/
	int max_width;
};
struct gstr str_new(void);
void str_free(struct gstr *gs);
void str_append(struct gstr *gs, const char *s);
void str_clear(struct gstr *gs);
void str_printf(struct gstr *gs, const char *fmt, ...);
const char *str_get(struct gstr *gs);

/* symbol.c */
void sym_clear_all_valid(void);
struct symbol *sym_choice_default(struct symbol *sym);
struct property *sym_get_range_prop(struct symbol *sym);
const char *sym_get_string_default(struct symbol *sym);
struct symbol *sym_check_deps(struct symbol *sym);
struct property *prop_alloc(enum prop_type type, struct symbol *sym);
struct symbol *prop_get_symbol(struct property *prop);

static inline tristate sym_get_tristate_value(struct symbol *sym)
{
	return sym->curr.tri;
}


static inline struct symbol *sym_get_choice_value(struct symbol *sym)
{
	return (struct symbol *)sym->curr.val;
}

static inline bool sym_set_choice_value(struct symbol *ch, struct symbol *chval)
{
	return sym_set_tristate_value(chval, yes);
}

static inline bool sym_is_choice(struct symbol *sym)
{
	return sym->flags & SYMBOL_CHOICE ? true : false;
}

static inline bool sym_is_choice_value(struct symbol *sym)
{
	return sym->flags & SYMBOL_CHOICEVAL ? true : false;
}

static inline bool sym_is_optional(struct symbol *sym)
{
	return sym->flags & SYMBOL_OPTIONAL ? true : false;
}

static inline bool sym_has_value(struct symbol *sym)
{
	return sym->flags & SYMBOL_DEF_USER ? true : false;
}

/* dependency_parser.c */
int elib_dependency();
void output_dependency(FILE *out, struct symbol *sym, char *prefix, char *orig);

#ifdef __cplusplus
}
#endif

#endif /* LKC_H */
