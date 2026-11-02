# SPDX-License-Identifier: GPL-2.0

"""
测试:提供.config文件,测试oldconfig命令下生成extend文件是否符合预期
"""
def test_extend_old(conf):

    assert conf.build_extend_config(mode='--oldconfig', dot_config='config') == 0
    assert conf.extend_config_contains('expected_extend_old_config')
    assert conf.extend_autoconf_contains('expected_extend_old_autoconf')

"""
测试:测试allyesconfig命令下生成extend文件是否符合预期
"""
def test_extend_allyes(conf):

    assert conf.build_extend_config(mode='--allyesconfig') == 0
    assert conf.extend_config_contains('expected_extend_notemplate_config')
    assert conf.extend_autoconf_contains('expected_extend_notemplate_autoconf')

"""
测试:提供指定的.config与autoconf.h文件生成路径,将所需的文件按指定路径生成
"""
def test_extend_buildpath(conf):

    assert conf.build_extend_config(mode='--allyesconfig',
                                    extend_autoconf='.config',
                                    extend_config='autoconf.h') == 0
    assert conf.extend_config_contains('expected_extend_notemplate_config')
    assert conf.extend_autoconf_contains('expected_extend_notemplate_autoconf')


"""
测试：正确提供模版文件
"""
def test_extend_template(conf):

    assert conf.render_extend_config(mode='--allyesconfig',
                                    extend_template='app_header_template') == 0
    assert conf.extend_config_contains('expected_extend_template_config')
    assert conf.extend_autoconf_contains('expected_extend_template_autoconf')

"""
测试：提供模版文件，但模版文件内容为空
"""
def test_extend_empty_template(conf):

    assert conf.render_extend_config(mode='--allyesconfig',
                                    extend_template='app_header_template_empty') == 0
    assert conf.extend_config_contains('expected_extend_notemplate_config')
    assert conf.extend_autoconf_contains('expected_extend_notemplate_autoconf')

"""
测试：未提供模版文件
"""
def test_extend_no_template(conf):

    assert conf.render_extend_config(mode='--allyesconfig') == 0
    assert conf.extend_config_contains('expected_extend_notemplate_config')
    assert conf.extend_autoconf_contains('expected_extend_notemplate_autoconf')

"""
测试：提供模版文件路径错误
"""
def test_extend_error_path_template(conf):

    assert conf.render_extend_config(mode='--allyesconfig',
                                    extend_template='error_path') == 0
    assert conf.stderr_contains('expected_extend_error_path_template_stderr')




