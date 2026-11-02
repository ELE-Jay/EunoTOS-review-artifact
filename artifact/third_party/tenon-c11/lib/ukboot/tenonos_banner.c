/* Copyright 2024 Hangzhou Yingyi Technology Co., Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ssANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <uk/plat/console.h>
#include <uk/config.h>

/*
 * Color palette
 */
#if CONFIG_LIBTNBOOT_BANNER_WELCOME_IMG_AND_TXT_CLR
/* Blue version (ANSI) */
#define C_RST UK_ANSI_MOD_RESET
#define C_W UK_ANSI_MOD_RESET UK_ANSI_MOD_COLORFG(UK_ANSI_COLOR_WHITE)
#define C_B UK_ANSI_MOD_RESET UK_ANSI_MOD_COLORFG(UK_ANSI_COLOR_BLUE)
#define C_R UK_ANSI_MOD_BOLD UK_ANSI_MOD_COLORFG(UK_ANSI_COLOR_RED)
#define C_Y UK_ANSI_MOD_BOLD UK_ANSI_MOD_COLORFG(UK_ANSI_COLOR_YELLOW)
#define C_G UK_ANSI_MOD_BOLD UK_ANSI_MOD_COLORFG(UK_ANSI_COLOR_GREEN)
#else
/* No colors */
#define C_RST ""
#define C_W C_RST
#define C_B C_RST
#define C_R C_RST
#define C_Y C_RST
#define C_G C_RST
#endif

void print_banner(FILE *out)
{
	// clang-format off
	fprintf(out, C_W);
	fprintf(out, "\n __          __  _                            _       _______                      ____   _____\n");
	fprintf(out, " \\ \\        / / | |                          | |     |__   __|                    / __ \\ / ____|\n");
	fprintf(out, "  \\ \\  /\\  / /__| | ___ ___  _ __ ___   ___  | |_ ___   | | ___ _ __   ___  _ __ | |  | | (___  \n");
	fprintf(out, "   \\ \\/  \\/ / _ \\ |/ __/ _ \\| '_ ` _ \\ / _ \\ | __/ _ \\  | |/ _ \\ '_ \\ / _ \\| '_ \\| |  | |\\___ \\ \n");
	fprintf(out, "    \\  /\\  /  __/ | (_| (_) | | | | | |  __/ | || (_) | | |  __/ | | | (_) | | | | |__| |____) |\n");
	fprintf(out, "     \\/  \\/ \\___|_|\\___\\___/|_| |_| |_|\\___|  \\__\\___/  |_|\\___|_| |_|\\___/|_| |_|\\____/|_____/ \n");
#if CONFIG_LIBTNBOOT_BANNER_WELCOME_IMG_AND_TXT || CONFIG_LIBTNBOOT_BANNER_WELCOME_IMG_AND_TXT_CLR
	fprintf(out, "\n\n\n"C_Y);
	fprintf(out, "                 ::::: :\n");
	fprintf(out, "             ::::::::  :::\n");
	fprintf(out, "            ::::::::: :::::\n");
	fprintf(out, "           .:::::::: ::::::::\n");
	fprintf(out, "           ::::::::  :::::::::\n");
	fprintf(out, "          ::::.      ::::::::.\n");
	fprintf(out, "           ::::::::::  ::::::            "C_B"        G:\n");
	fprintf(out, C_Y"            ::::::::::: ::::          "C_B"        GGGGGLG;\n");
	fprintf(out, C_Y"              ::::::::::  :.          "C_B"     DGGGGGGGGGGGL\n");
	fprintf(out, C_Y"                ::::::::::            "C_B"  GDGGGGGGGGGGGGGG.E\n");
	fprintf(out, "                                     GDDDDGGGGGGGGGGG:KWWW\n");
	fprintf(out, "                                  DDDDDDDDDGGGGGGGGGG: WWW\n");
	fprintf(out, "                                 W  DDDDDDDDGGGGGGGGGGGG L       GGGG\n");
	fprintf(out, "                GGG.              WWW  DDDDDDDGGGGGGGGGGGGG   LLLLLLLLLL\n");
	fprintf(out, "             GDDDDGGGG.           KWWWWW  DDDDDGGGGGGGGGGGGGGGLLLLLLLLLLLLG\n");
	fprintf(out, "          DDDDDDDDGGGGGGGj        DWK  DDDDDDDDDGGGGGGGGGGGGGGGLLLLLLLLLLLLLL\n");
	fprintf(out, "          DEDDDDDDDDGGGGGGGGG       DDDDDDDDDDDDGGGGGGGGGGGGGGGGLLLLLLLLLL  ED\n");
	fprintf(out, "        LGL  LDDDDDDDGGGGGGGGGG  EEEDDDDDDDDDDDDDDGGGGGGGGGGGGGGGGLLLLG  DDDDD\n");
	fprintf(out, "        GLLLGG. :DDDDDGGGGGG  EEEEEEEDDDDDDDDDDD  GGL :GGGGGGGGGGGLG  DDDDDDDD\n");
	fprintf(out, "        LLLLLLGGLt  GDDGG  KEEEEEEEEEDDDDDDDD  DDDDDGGGG  GGGGGGG  DDDDDDDDDDD\n");
	fprintf(out, "        LLLLLGGGGGGGG   DKKKEEEEEEEEEEEDDE  DDDDDDDDGGGGGGG  G  DDDDDDDDDDDDDD\n");
	fprintf(out, "        LLLLGGGGGGGGGGG   KKKEEEEEEEEEE  t K  DDDDDDDGGGGGG   DDDDDDDDDDDDGGGG;\n");
	fprintf(out, "         LGLGGGGGGGGGGG GGD  KEEEEEE  iEEE;KKKK, LDDDDDG. EEE DDDDDDGGGGGGGGt\n");
	fprintf(out, "            GGGGGGGGGGG GGGGGD  E  LKKKKKKLWWKKKEEi t. KEEEEE DGGGGGGGGGGt\n");
	fprintf(out, C_B"              GGGGGGGGG GGGDDDDD jKKKKKKKKEEWWKKKEEEjDEEEEEEE GGGGGGGGj "C_G"                 :j\n");
	fprintf(out, C_B"              GGGGGGGGG GDDDDDDD .KWWWWWWWWGWWWKKKEEE,EEEEEEEfiGGGGj    "C_G"        f LLLLLLLLLL\n");
	fprintf(out, C_B"              GGGGGGGGG GDDDDDDD. WWWWWWWWW;WWWWKKKEE EEEEEDED:Gf       "C_G"        LL LLLLLLLLLL\n");
	fprintf(out, C_B"          :WW GGGGGGGGG fGDDDDDD. WWWWWWWK  DKWWWKKKE DDDDDDDD          "C_G"       LLLL LLLLLLLLLL.\n");
	fprintf(out, C_B"        .WWWW GGGGGGGGGGDG iDDDDt WWWWK iWWKKK jKWKKK DDDDDDDD          "C_G"      LLLLLL LLLLLLLLLLL\n");
	fprintf(out, C_B"        GG  W GGGGGGGDGDDDDDD ,DD WE ,WWWWKKKEEEE ,KK DDDDDDDD K;       "C_G"     LLLLLLLG  ;       f\n");
	fprintf(out, C_B"        GGGGG GGGGGGGDDDDDDDDDDD  jWWWWWKKKKEEEEDDDD  DDDDDDDD WWWW:    "C_G"     iLLLLLLL :LLLLLLLL\n");
	fprintf(out, C_B"        GGGGGGGGGGGDDDDDDDDDDDDDDDD  WKKKKKEEEEDDD  D DDDDDDDD WWWWWWW  "C_G"       LLLLLG LLLLLLLL\n");
	fprintf(out, C_B"        GGGGGGGGGGDDDDDDDDDDDDDDDDEEEE  KEEEEED  DDDD DDDDDDDD WWWW  DG "C_G"        LLLL LLLLLLLL\n");
	fprintf(out, C_B"        GGGGGGGGGGGDDDDDDDDDDDDDDEEEEEEEE  D  DDDDDDD DDDDDDGG K  GGGGG "C_G"         LL LLLLLLLL.\n");
	fprintf(out, C_B"          GGGGGGGDDDDDD  GDDDDDDEEEEEEEEEEE DDDDDDDDG GGGGGGGGjLGGGGGGG "C_G"           jf\n");
	fprintf(out, C_B"             DGDDDDDDDD WWW jDDEEEEEEEEEEEE DGDDDGGGG GGGGGGGGGGGGGGGGG\n");
	fprintf(out, "                GDDDDDD WWWW;  ,EEEEEEEEEEE GGGGGGGGG GGGGGGGGGGGGGGGGG\n");
	fprintf(out, "                   fDDD KW         EEEEEEKK GGGGGGGG  GGGGGGGGGGGGGGGGG\n");
	fprintf(out, "                      ;           GD  EEKKK GGGGG  DGGGGGGGGGGGGGGGGGGG\n");
	fprintf(out, "                                  DDDDD: KK GG  DGGGGGGGGGGGGGGGGGGGGGG\n");
	fprintf(out, "                                  GDDDDDDE   jGGGGGGGGGGGGGGGG.GGGGGGGG\n");
	fprintf(out, "                                  GDDDDDDEE GGGGGGGGGGGGGGG  W GGGGGGGG\n");
	fprintf(out, "                                  DDDDDDEEE GGGGGGGGGGGL. KWWW GLLGGLf\n");
	fprintf(out, C_R"            ,LLLLLLLLLL         "C_B"  DDDDDDEEE LGGGGGGGGG   iWWWW GLLL\n");
	fprintf(out, C_R"           LL LLLLLLLLLL        "C_B"  DDDDDDEEE.GGLLLGGGGL       . L\n");
	fprintf(out, C_R"          GLLL LLLLLLLLLLL      "C_B"  DDDDDEEEE:GLLLLLLLLL\n");
	fprintf(out, C_R"          LLLLG ,LLLLLLLLLL     "C_B"  DDDDDEEEE,GLLLLLLLLL\n");
	fprintf(out, C_R"         LLLLLLLL LLLLLLt:      "C_B"  DDDDDEEEE;GLLLLLLLLL\n");
	fprintf(out, C_R"         LLLLLLLL. fLLLLLLLL    "C_B"   .DDEEEEEtLLLLLLG;\n");
	fprintf(out, C_R"          LLLLLLL LLLLLLLLL     "C_B"       EEEEfLLLL;\n");
	fprintf(out, C_R"           LLLLL tLLLLLLLL.     "C_B"          KGLi\n");
	fprintf(out, C_R"            LLLf LLLLLLLLL\n");
	fprintf(out, C_R"             GL LLLLLLLLL\n");
#endif
	// clang-format on
	fprintf(out, C_RST);
	fprintf(out,
		"                                                      %45s",
		"Powered by TenonOS (" STRINGIFY(TN_FULLVERSION) ")\n\n\n");
}

