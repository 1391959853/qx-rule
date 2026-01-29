#!/usr/bin/env python3
"""
Quantumult X 规则高级转换系统
支持分流规则和重写规则中的DOMAIN转换
"""

import os
import re
import sys
import json
import requests
import configparser
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Set, Optional
from urllib.parse import urlparse, urljoin
import logging
import hashlib

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('conversion.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AdvancedRuleConverter:
    def __init__(self, github_token: str = None):
        """
        初始化高级规则转换器
        
        Args:
            github_token: GitHub Personal Access Token
        """
        self.github_token = github_token
        self.session = requests.Session()
        
        if github_token:
            self.session.headers.update({
                'Authorization': f'token {github_token}',
                'User-Agent': 'QX-Rule-Converter/2.0'
            })
        else:
            self.session.headers.update({
                'User-Agent': 'QX-Rule-Converter/2.0'
            })
        
        # 分流规则转换映射（DOMAIN -> HOST）
        self.filter_rule_conversions = {
            # DOMAIN -> HOST
            r'(?i)^DOMAIN,': 'HOST,',
            r'(?i)^DOMAIN-SUFFIX,': 'HOST-SUFFIX,',
            r'(?i)^DOMAIN-KEYWORD,': 'HOST-KEYWORD,',
            # 确保其他规则类型大写
            r'(?i)^IP-CIDR,': 'IP-CIDR,',
            r'(?i)^IP-CIDR6,': 'IP-CIDR6,',
            r'(?i)^GEOIP,': 'GEOIP,',
            r'(?i)^URL-REGEX,': 'URL-REGEX,',
            r'(?i)^PROCESS-NAME,': 'PROCESS-NAME,',
        }
        
        # 重写规则转换映射
        self.rewrite_rule_conversions = {
            # 重写规则中的DOMAIN匹配
            r'(?i)^DOMAIN,([^,]+),([^,]+)(?:,([^,]+))?$': self._convert_rewrite_domain,
            r'(?i)^DOMAIN-SUFFIX,([^,]+),([^,]+)(?:,([^,]+))?$': self._convert_rewrite_domain_suffix,
            r'(?i)^DOMAIN-KEYWORD,([^,]+),([^,]+)(?:,([^,]+))?$': self._convert_rewrite_domain_keyword,
            # URL正则重写规则（保持不变）
            r'^\^https?://': None,  # 标记为URL重写规则
        }
        
        # 策略映射
        self.policy_mappings = {
            'DIRECT': 'DIRECT',
            'PROXY': 'PROXY',
            'REJECT': 'REJECT',
            '广告拦截': 'REJECT',
            '去广告': 'REJECT',
            '全球直连': 'DIRECT',
            '国内直连': 'DIRECT',
            '国外代理': 'PROXY',
            '国外网站': 'PROXY',
            'no-resolve': 'no-resolve',
        }
        
        # 已处理的规则哈希集合
        self.processed_hashes = {
            'filter': set(),
            'rewrite': set()
        }
        
        # 转换统计
        self.stats = {
            'total_sources': 0,
            'successful_downloads': 0,
            'failed_downloads': [],
            'filter_rules_count': 0,
            'rewrite_rules_count': 0,
            'domain_conversions': 0,
            'source_repos': []
        }
    
    def parse_rule_ini(self, ini_path: str) -> Dict:
        """
        解析rule.ini文件
        
        Args:
            ini_path: rule.ini文件路径
            
        Returns:
            解析后的配置字典
        """
        config = configparser.ConfigParser()
        
        # 支持多行urls
        try:
            config.read(ini_path, encoding='utf-8')
        except Exception as e:
            logger.error(f"解析INI文件失败: {str(e)}")
            # 尝试手动解析
            return self._manual_parse_ini(ini_path)
        
        result = {
            'filter_remote': [],
            'rewrite_remote': [],
            'other_sections': {}
        }
        
        # 处理[filter_remote]
        if 'filter_remote' in config:
            urls_text = config['filter_remote'].get('urls', '')
            # 处理多行URL（每行一个）
            urls = []
            for line in urls_text.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    # 一行可能有多个URL（空格分隔）
                    for url in line.split():
                        if url and not url.startswith('#'):
                            urls.append(url.strip())
            result['filter_remote'] = urls
        
        # 处理[rewrite_remote]
        if 'rewrite_remote' in config:
            urls_text = config['rewrite_remote'].get('urls', '')
            urls = []
            for line in urls_text.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    for url in line.split():
                        if url and not url.startswith('#'):
                            urls.append(url.strip())
            result['rewrite_remote'] = urls
        
        # 处理其他节
        for section in config.sections():
            if section not in ['filter_remote', 'rewrite_remote']:
                result['other_sections'][section] = dict(config[section])
        
        logger.info(f"解析到 {len(result['filter_remote'])} 个分流链接和 {len(result['rewrite_remote'])} 个重写链接")
        return result
    
    def _manual_parse_ini(self, ini_path: str) -> Dict:
        """
        手动解析INI文件（当configparser解析失败时）
        
        Args:
            ini_path: ini文件路径
            
        Returns:
            解析后的配置字典
        """
        result = {
            'filter_remote': [],
            'rewrite_remote': [],
            'other_sections': {}
        }
        
        current_section = None
        
        with open(ini_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # 跳过空行和注释
                if not line or line.startswith('#'):
                    continue
                
                # 检查节标题
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1]
                    continue
                
                # 处理URL
                if current_section == 'filter_remote':
                    if line.startswith('urls') or '=' in line:
                        # 提取URL部分
                        if '=' in line:
                            urls_part = line.split('=', 1)[1].strip()
                        else:
                            urls_part = line
                        
                        # 分割URL
                        for url in urls_part.split():
                            url = url.strip()
                            if url and not url.startswith('#'):
                                result['filter_remote'].append(url)
                
                elif current_section == 'rewrite_remote':
                    if line.startswith('urls') or '=' in line:
                        if '=' in line:
                            urls_part = line.split('=', 1)[1].strip()
                        else:
                            urls_part = line
                        
                        for url in urls_part.split():
                            url = url.strip()
                            if url and not url.startswith('#'):
                                result['rewrite_remote'].append(url)
        
        logger.info(f"手动解析到 {len(result['filter_remote'])} 个分流链接和 {len(result['rewrite_remote'])} 个重写链接")
        return result
    
    def download_content(self, url: str) -> Optional[Tuple[str, str, str]]:
        """
        下载内容
        
        Args:
            url: 下载链接
            
        Returns:
            (内容类型, 内容, 实际URL) 或 None
        """
        try:
            logger.info(f"下载: {url}")
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                content = response.text
                
                # 判断内容类型
                content_type = self._detect_content_type(content, url)
                
                # 记录原始仓库信息
                repo_info = self._extract_repo_info(url)
                if repo_info not in self.stats['source_repos']:
                    self.stats['source_repos'].append(repo_info)
                
                logger.info(f"下载成功: {len(content)} 字节 ({content_type})")
                return content_type, content, response.url
            else:
                logger.error(f"下载失败 {url}: {response.status_code}")
                self.stats['failed_downloads'].append({
                    'url': url,
                    'error': f"HTTP {response.status_code}"
                })
                
        except Exception as e:
            logger.error(f"下载异常 {url}: {str(e)}")
            self.stats['failed_downloads'].append({
                'url': url,
                'error': str(e)
            })
        
        return None
    
    def _detect_content_type(self, content: str, url: str) -> str:
        """
        检测内容类型
        
        Args:
            content: 内容
            url: 原始URL
            
        Returns:
            内容类型: 'filter', 'rewrite', 'mixed', 'unknown'
        """
        content_lower = content.lower()
        
        # 检查是否是重写规则
        rewrite_indicators = [
            '^http',  # URL重写
            ' url ',  # 重写规则格式
            'reject',  # 拒绝规则
            '302', '307',  # 重定向
            '[rewrite]',  # 重写节
        ]
        
        # 检查是否是分流规则
        filter_indicators = [
            'domain,',
            'host,',
            'ip-cidr,',
            'geoip,',
            'url-regex,',
            '[filter]',
            '[rule]',
        ]
        
        rewrite_count = sum(1 for indicator in rewrite_indicators if indicator in content_lower)
        filter_count = sum(1 for indicator in filter_indicators if indicator in content_lower)
        
        # 根据URL后缀判断
        url_lower = url.lower()
        if any(ext in url_lower for ext in ['.list', '.txt', '.rules']):
            return 'filter'
        elif any(ext in url_lower for ext in ['.conf', '.rewrite', '.js']):
            return 'rewrite'
        
        # 根据内容判断
        if rewrite_count > filter_count:
            return 'rewrite'
        elif filter_count > rewrite_count:
            return 'filter'
        elif rewrite_count > 0 and filter_count > 0:
            return 'mixed'
        else:
            return 'unknown'
    
    def _extract_repo_info(self, url: str) -> Dict:
        """
        从URL提取仓库信息
        
        Args:
            url: 原始URL
            
        Returns:
            仓库信息字典
        """
        try:
            # GitHub链接
            github_match = re.search(r'github\.com/([^/]+)/([^/]+)', url)
            if github_match:
                owner = github_match.group(1)
                repo = github_match.group(2)
                full_repo = f"{owner}/{repo}"
                
                # 获取仓库描述（如果可能）
                repo_desc = self._get_github_repo_desc(full_repo)
                
                return {
                    'type': 'github',
                    'owner': owner,
                    'repo': repo,
                    'full_repo': full_repo,
                    'url': f"https://github.com/{full_repo}",
                    'description': repo_desc,
                    'raw_url': url
                }
            
            # GitLab链接
            gitlab_match = re.search(r'gitlab\.com/([^/]+)/([^/]+)', url)
            if gitlab_match:
                owner = gitlab_match.group(1)
                repo = gitlab_match.group(2)
                full_repo = f"{owner}/{repo}"
                
                return {
                    'type': 'gitlab',
                    'owner': owner,
                    'repo': repo,
                    'full_repo': full_repo,
                    'url': f"https://gitlab.com/{full_repo}",
                    'raw_url': url
                }
            
            # 其他链接
            return {
                'type': 'other',
                'url': url,
                'raw_url': url
            }
            
        except Exception as e:
            logger.warning(f"提取仓库信息失败 {url}: {str(e)}")
        
        return {
            'type': 'unknown',
            'url': url,
            'raw_url': url
        }
    
    def _get_github_repo_desc(self, repo: str) -> str:
        """
        获取GitHub仓库描述
        
        Args:
            repo: 仓库名（owner/repo）
            
        Returns:
            仓库描述或空字符串
        """
        try:
            if self.github_token:
                api_url = f"https://api.github.com/repos/{repo}"
                headers = {'Authorization': f'token {self.github_token}'}
                
                response = self.session.get(api_url, headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    return data.get('description', '')
        except:
            pass
        return ''
    
    def convert_filter_rule(self, line: str) -> str:
        """
        转换分流规则行
        
        Args:
            line: 原始规则行
            
        Returns:
            转换后的规则行
        """
        original_line = line.strip()
        
        # 空行或注释行
        if not original_line or original_line.startswith('#'):
            return original_line
        
        # 跳过节标题
        if original_line.startswith('[') and original_line.endswith(']'):
            return original_line
        
        # 跳过hostname行
        if original_line.lower().startswith('hostname'):
            return original_line
        
        # 检查是否为DOMAIN相关规则
        converted_line = original_line
        
        # 应用DOMAIN -> HOST转换
        domain_converted = False
        for pattern, replacement in self.filter_rule_conversions.items():
            if re.match(pattern, converted_line, re.IGNORECASE):
                converted_line = re.sub(pattern, replacement, converted_line, flags=re.IGNORECASE)
                if 'DOMAIN' in pattern.upper():
                    domain_converted = True
                break
        
        # 如果是DOMAIN转换，更新统计
        if domain_converted:
            self.stats['domain_conversions'] += 1
        
        # 处理策略映射
        parts = converted_line.split(',')
        if len(parts) >= 3:
            policy = parts[-1].strip()
            mapped_policy = self.policy_mappings.get(policy.upper(), policy.upper())
            parts[-1] = mapped_policy
            converted_line = ','.join(parts)
        
        # 确保规则类型大写
        if ',' in converted_line:
            rule_type = converted_line.split(',')[0]
            if rule_type.isalpha():
                converted_line = rule_type.upper() + converted_line[len(rule_type):]
        
        return converted_line
    
    def convert_rewrite_rule(self, line: str) -> str:
        """
        转换重写规则行
        
        Args:
            line: 原始规则行
            
        Returns:
            转换后的规则行
        """
        original_line = line.strip()
        
        # 空行或注释行
        if not original_line or original_line.startswith('#'):
            return original_line
        
        # 跳过节标题
        if original_line.startswith('[') and original_line.endswith(']'):
            return original_line
        
        # 跳过hostname行
        if original_line.lower().startswith('hostname'):
            return original_line
        
        # 检查是否是DOMAIN类型的重写规则
        for pattern, converter in self.rewrite_rule_conversions.items():
            if converter is None:
                # 只是标记，不需要转换
                if re.match(pattern, original_line):
                    return original_line
            else:
                match = re.match(pattern, original_line, re.IGNORECASE)
                if match:
                    try:
                        converted_line = converter(match.groups())
                        if converted_line:
                            self.stats['domain_conversions'] += 1
                            return converted_line
                    except Exception as e:
                        logger.warning(f"转换重写规则失败: {original_line}, 错误: {str(e)}")
        
        # 检查是否是URL重写规则（保持原样）
        if ' url ' in original_line:
            return original_line
        
        # 检查是否是其他类型的重写规则
        if original_line.startswith(('http', '^', 'hostname', 'mitm')):
            return original_line
        
        # 其他情况，尝试应用DOMAIN转换
        converted_line = original_line
        for pattern, replacement in self.filter_rule_conversions.items():
            if 'DOMAIN' in pattern and re.match(pattern, converted_line, re.IGNORECASE):
                converted_line = re.sub(pattern, replacement, converted_line, flags=re.IGNORECASE)
                self.stats['domain_conversions'] += 1
                break
        
        return converted_line
    
    def _convert_rewrite_domain(self, groups: Tuple) -> str:
        """转换重写规则中的DOMAIN"""
        domain, action, *extra = groups
        result = f"HOST,{domain},{action.upper()}"
        if extra and extra[0]:
            result += f",{extra[0]}"
        return result
    
    def _convert_rewrite_domain_suffix(self, groups: Tuple) -> str:
        """转换重写规则中的DOMAIN-SUFFIX"""
        suffix, action, *extra = groups
        result = f"HOST-SUFFIX,{suffix},{action.upper()}"
        if extra and extra[0]:
            result += f",{extra[0]}"
        return result
    
    def _convert_rewrite_domain_keyword(self, groups: Tuple) -> str:
        """转换重写规则中的DOMAIN-KEYWORD"""
        keyword, action, *extra = groups
        result = f"HOST-KEYWORD,{keyword},{action.upper()}"
        if extra and extra[0]:
            result += f",{extra[0]}"
        return result
    
    def process_filter_content(self, content: str, source_url: str = "") -> List[str]:
        """
        处理分流规则内容
        
        Args:
            content: 原始内容
            source_url: 源URL
            
        Returns:
            处理后的规则列表
        """
        lines = content.split('\n')
        processed_lines = []
        source_comment = f"# Source: {source_url}" if source_url else ""
        
        for line in lines:
            line = line.rstrip()
            
            if not line:
                processed_lines.append("")
                continue
            
            # 处理规则行
            converted_line = self.convert_filter_rule(line)
            
            # 生成哈希用于去重
            rule_hash = hashlib.md5(converted_line.encode('utf-8')).hexdigest()
            
            if rule_hash not in self.processed_hashes['filter']:
                self.processed_hashes['filter'].add(rule_hash)
                processed_lines.append(converted_line)
                self.stats['filter_rules_count'] += 1
            else:
                # 规则重复，添加注释
                if not converted_line.startswith('#') and converted_line:
                    processed_lines.append(f"# {converted_line}  # [重复规则已跳过]")
                else:
                    processed_lines.append(converted_line)
        
        # 添加来源注释
        if source_comment and processed_lines:
            for i, line in enumerate(processed_lines):
                if line and not line.startswith('#'):
                    processed_lines.insert(i, source_comment)
                    processed_lines.insert(i + 1, "")
                    break
            else:
                processed_lines.insert(0, source_comment)
                processed_lines.insert(1, "")
        
        return processed_lines
    
    def process_rewrite_content(self, content: str, source_url: str = "") -> List[str]:
        """
        处理重写规则内容
        
        Args:
            content: 原始内容
            source_url: 源URL
            
        Returns:
            处理后的规则列表
        """
        lines = content.split('\n')
        processed_lines = []
        source_comment = f"# Source: {source_url}" if source_url else ""
        
        for line in lines:
            line = line.rstrip()
            
            if not line:
                processed_lines.append("")
                continue
            
            # 处理规则行
            converted_line = self.convert_rewrite_rule(line)
            
            # 生成哈希用于去重
            rule_hash = hashlib.md5(converted_line.encode('utf-8')).hexdigest()
            
            if rule_hash not in self.processed_hashes['rewrite']:
                self.processed_hashes['rewrite'].add(rule_hash)
                processed_lines.append(converted_line)
                self.stats['rewrite_rules_count'] += 1
            else:
                # 规则重复，添加注释
                if not converted_line.startswith('#') and converted_line:
                    processed_lines.append(f"# {converted_line}  # [重复规则已跳过]")
                else:
                    processed_lines.append(converted_line)
        
        # 添加来源注释
        if source_comment and processed_lines:
            for i, line in enumerate(processed_lines):
                if line and not line.startswith('#'):
                    processed_lines.insert(i, source_comment)
                    processed_lines.insert(i + 1, "")
                    break
            else:
                processed_lines.insert(0, source_comment)
                processed_lines.insert(1, "")
        
        return processed_lines
    
    def process_mixed_content(self, content: str, source_url: str = "") -> Dict[str, List[str]]:
        """
        处理混合内容（包含分流和重写规则）
        
        Args:
            content: 原始内容
            source_url: 源URL
            
        Returns:
            处理后的规则字典 {'filter': [], 'rewrite': []}
        """
        result = {
            'filter': [],
            'rewrite': []
        }
        
        lines = content.split('\n')
        current_section = None
        buffer = []
        
        for line in lines:
            line = line.rstrip()
            
            # 检查节标题
            if line.startswith('[') and line.endswith(']'):
                # 处理之前的缓冲区
                if buffer and current_section:
                    if current_section in ['filter', 'rules', 'filter_remote']:
                        result['filter'].extend(self.process_filter_content('\n'.join(buffer), source_url))
                        result['filter'].append("")
                    elif current_section in ['rewrite', 'rewrite_remote', 'rewrite_local']:
                        result['rewrite'].extend(self.process_rewrite_content('\n'.join(buffer), source_url))
                        result['rewrite'].append("")
                
                # 更新当前节
                section_name = line[1:-1].lower()
                if 'filter' in section_name or 'rules' in section_name:
                    current_section = 'filter'
                elif 'rewrite' in section_name:
                    current_section = 'rewrite'
                else:
                    current_section = None
                
                buffer = [line]
                continue
            
            # 添加到缓冲区
            buffer.append(line)
        
        # 处理最后一个缓冲区
        if buffer and current_section:
            if current_section == 'filter':
                result['filter'].extend(self.process_filter_content('\n'.join(buffer), source_url))
            elif current_section == 'rewrite':
                result['rewrite'].extend(self.process_rewrite_content('\n'.join(buffer), source_url))
        
        return result
    
    def process_all_urls(self, ini_path: str, output_dir: str = "rules") -> Dict:
        """
        处理所有URL
        
        Args:
            ini_path: rule.ini文件路径
            output_dir: 输出目录
            
        Returns:
            处理结果统计
        """
        # 解析INI文件
        config = self.parse_rule_ini(ini_path)
        
        # 准备输出
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # 初始化输出缓冲区
        filter_output = []
        rewrite_output = []
        
        # 添加文件头
        filter_header = self._generate_file_header("Quantumult X 分流规则", ini_path)
        rewrite_header = self._generate_file_header("Quantumult X 重写规则", ini_path)
        
        filter_output.extend(filter_header)
        rewrite_output.extend(rewrite_header)
        
        # 处理分流规则链接
        logger.info(f"开始处理分流规则 ({len(config['filter_remote'])} 个链接)")
        for url in config['filter_remote']:
            result = self.download_content(url)
            if result:
                content_type, content, actual_url = result
                
                if content_type in ['filter', 'unknown']:
                    rules = self.process_filter_content(content, actual_url)
                    filter_output.extend(rules)
                    filter_output.append("")
                elif content_type == 'rewrite':
                    rules = self.process_rewrite_content(content, actual_url)
                    rewrite_output.extend(rules)
                    rewrite_output.append("")
                elif content_type == 'mixed':
                    mixed_result = self.process_mixed_content(content, actual_url)
                    filter_output.extend(mixed_result['filter'])
                    rewrite_output.extend(mixed_result['rewrite'])
                
                self.stats['successful_downloads'] += 1
            
            self.stats['total_sources'] += 1
        
        # 处理重写规则链接
        logger.info(f"开始处理重写规则 ({len(config['rewrite_remote'])} 个链接)")
        for url in config['rewrite_remote']:
            result = self.download_content(url)
            if result:
                content_type, content, actual_url = result
                
                if content_type in ['rewrite', 'unknown']:
                    rules = self.process_rewrite_content(content, actual_url)
                    rewrite_output.extend(rules)
                    rewrite_output.append("")
                elif content_type == 'filter':
                    rules = self.process_filter_content(content, actual_url)
                    filter_output.extend(rules)
                    filter_output.append("")
                elif content_type == 'mixed':
                    mixed_result = self.process_mixed_content(content, actual_url)
                    filter_output.extend(mixed_result['filter'])
                    rewrite_output.extend(mixed_result['rewrite'])
                
                self.stats['successful_downloads'] += 1
            
            self.stats['total_sources'] += 1
        
        # 保存分流规则
        filter_file = output_path / "filter_rules.conf"
        with open(filter_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(filter_output))
        
        # 保存重写规则
        rewrite_file = output_path / "rewrite_rules.conf"
        with open(rewrite_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(rewrite_output))
        
        # 添加原作者仓库链接
        self._add_author_links(filter_file, rewrite_file, config)
        
        # 生成统计信息
        stats = self._generate_stats()
        
        logger.info(f"处理完成！")
        logger.info(f"分流规则: {self.stats['filter_rules_count']} 条")
        logger.info(f"重写规则: {self.stats['rewrite_rules_count']} 条")
        logger.info(f"DOMAIN转换: {self.stats['domain_conversions']} 次")
        
        return stats
    
    def _generate_file_header(self, title: str, ini_path: str) -> List[str]:
        """
        生成文件头
        
        Args:
            title: 文件标题
            ini_path: ini文件路径
            
        Returns:
            文件头行列表
        """
        return [
            "# " + "=" * 50,
            f"# {title}",
            "# " + "=" * 50,
            f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# 配置文件: {ini_path}",
            "# 说明: 所有DOMAIN规则已统一转换为HOST规则",
            "# 注意: 完全相同的规则已自动去重",
            "# " + "=" * 50,
            ""
        ]
    
    def _add_author_links(self, filter_file: Path, rewrite_file: Path, config: Dict):
        """
        添加原作者仓库链接
        
        Args:
            filter_file: 分流规则文件
            rewrite_file: 重写规则文件
            config: 配置信息
        """
        # 收集所有仓库链接
        all_repos = []
        
        # 从分流链接提取
        for url in config['filter_remote']:
            repo_info = self._extract_repo_info(url)
            if repo_info not in all_repos:
                all_repos.append(repo_info)
        
        # 从重写链接提取
        for url in config['rewrite_remote']:
            repo_info = self._extract_repo_info(url)
            if repo_info not in all_repos:
                all_repos.append(repo_info)
        
        # 生成仓库链接部分
        author_section = [
            "",
            "# " + "=" * 50,
            "# 原作者仓库链接 (点击即可前往)",
            "# " + "=" * 50,
            ""
        ]
        
        for i, repo in enumerate(all_repos, 1):
            if repo['type'] == 'github':
                repo_name = repo.get('full_repo', repo.get('repo', 'GitHub仓库'))
                repo_desc = repo.get('description', '')
                desc_text = f" - {repo_desc}" if repo_desc else ""
                
                author_section.append(f"# {i}. [{repo_name}]({repo['url']}){desc_text}")
                author_section.append(f"#    规则链接: {repo['raw_url']}")
            elif repo['type'] == 'gitlab':
                author_section.append(f"# {i}. GitLab: {repo['url']}")
                author_section.append(f"#    规则链接: {repo['raw_url']}")
            else:
                author_section.append(f"# {i}. 规则链接: {repo['raw_url']}")
            author_section.append("")
        
        author_section.append("# " + "=" * 50)
        author_section.append("# 感谢所有规则作者的贡献！")
        author_section.append("# " + "=" * 50)
        
        # 添加到文件
        author_text = '\n'.join(author_section)
        
        # 添加到分流规则文件
        with open(filter_file, 'a', encoding='utf-8') as f:
            f.write('\n' + author_text)
        
        # 添加到重写规则文件
        with open(rewrite_file, 'a', encoding='utf-8') as f:
            f.write('\n' + author_text)
    
    def _generate_stats(self) -> Dict:
        """
        生成统计信息
        
        Returns:
            统计信息字典
        """
        stats = self.stats.copy()
        
        # 计算成功率
        if stats['total_sources'] > 0:
            stats['success_rate'] = (stats['successful_downloads'] / stats['total_sources']) * 100
        else:
            stats['success_rate'] = 0
        
        # 格式化时间
        stats['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 添加额外信息
        stats['output_files'] = ['filter_rules.conf', 'rewrite_rules.conf']
        
        return stats
    
    def generate_readme(self, stats: Dict, readme_path: str = "README.md"):
        """
        生成美观的README
        
        Args:
            stats: 统计信息
            readme_path: README文件路径
        """
        try:
            # 读取现有README或创建新内容
            if Path(readme_path).exists():
                with open(readme_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            else:
                content = "# Quantumult X 规则自动转换仓库\n\n"
            
            # 生成更新日志部分
            update_section = self._generate_update_section(stats)
            
            # 查找或创建更新日志部分
            pattern = r'(<!-- UPDATE_LOG_START -->[\s\S]*?<!-- UPDATE_LOG_END -->)'
            
            if re.search(pattern, content):
                # 替换现有日志
                content = re.sub(pattern, update_section, content)
            else:
                # 在文件开头添加
                content = content.replace("# Quantumult X 规则自动转换仓库\n\n", 
                                        "# Quantumult X 规则自动转换仓库\n\n" + update_section + "\n\n")
            
            # 保存README
            with open(readme_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"README已更新: {readme_path}")
            
        except Exception as e:
            logger.error(f"生成README失败: {str(e)}")
    
    def _generate_update_section(self, stats: Dict) -> str:
        """
        生成更新日志部分
        
        Args:
            stats: 统计信息
            
        Returns:
            Markdown格式的更新日志
        """
        # 生成徽章
        badges = [
            f"![最新更新](https://img.shields.io/badge/更新-{stats['timestamp'].replace(' ', '--')}-blue)",
            f"![分流规则](https://img.shields.io/badge/分流-{stats['filter_rules_count']}条-green)",
            f"![重写规则](https://img.shields.io/badge/重写-{stats['rewrite_rules_count']}条-orange)",
            f"![DOMAIN转换](https://img.shields.io/badge/DOMAIN转换-{stats['domain_conversions']}次-yellow)",
            f"![成功率](https://img.shields.io/badge/成功率-{stats['success_rate']:.1f}%25-brightgreen)"
        ]
        
        if stats['failed_downloads']:
            badges.append(f"![失败链接](https://img.shields.io/badge/失败-{len(stats['failed_downloads'])}个-red)")
        
        # 生成规则来源列表
        repo_table = []
        for repo in stats['source_repos']:
            if repo['type'] == 'github':
                repo_name = repo.get('full_repo', repo.get('repo', 'GitHub仓库'))
                repo_link = f"[{repo_name}]({repo['url']})"
                repo_desc = repo.get('description', '')
                repo_table.append(f"| {repo_link} | {repo_desc} | GitHub |")
            elif repo['type'] == 'gitlab':
                repo_table.append(f"| [{repo.get('full_repo', 'GitLab仓库')}]({repo['url']}) | - | GitLab |")
            else:
                repo_table.append(f"| {repo['url']} | - | 其他 |")
        
        # 生成失败列表
        failed_list = []
        if stats['failed_downloads']:
            for failed in stats['failed_downloads']:
                failed_list.append(f"- `{failed['url'][:50]}...` - {failed['error']}")
        
        return f"""<!-- UPDATE_LOG_START -->
## 📋 自动更新日志

### 🚀 最新更新 ({stats['timestamp']})

{' '.join(badges)}

### 📊 转换统计

| 项目 | 数量/状态 |
|------|-----------|
| 总链接数 | {stats['total_sources']} |
| 成功下载 | {stats['successful_downloads']} |
| 失败下载 | {len(stats['failed_downloads'])} |
| 分流规则数 | {stats['filter_rules_count']} |
| 重写规则数 | {stats['rewrite_rules_count']} |
| DOMAIN转换次数 | {stats['domain_conversions']} |
| 规则重复过滤 | 已启用 |
| 转换成功率 | {stats['success_rate']:.1f}% |

### 📁 输出文件

| 文件类型 | 文件名 | 规则数量 | 说明 |
|----------|--------|----------|------|
| 分流规则 | `rules/filter_rules.conf` | {stats['filter_rules_count']} | 所有分流规则，DOMAIN已转为HOST |
| 重写规则 | `rules/rewrite_rules.conf` | {stats['rewrite_rules_count']} | 所有重写规则，DOMAIN已转为HOST |

### 🔗 规则来源仓库

| 仓库 | 描述 | 类型 |
|------|------|------|
{chr(10).join(repo_table)}

{f"### ❌ 下载失败列表{f"{chr(10)}{chr(10).join(failed_list)}" if failed_list else ""}

### 🔄 转换规则说明

1. **DOMAIN转换**:
   - `DOMAIN` → `HOST`
   - `DOMAIN-SUFFIX` → `HOST-SUFFIX`
   - `DOMAIN-KEYWORD` → `HOST-KEYWORD`
   
2. **规则处理**:
   - 分流规则和重写规则分开处理
   - 完全相同的规则自动去重
   - 规则类型统一为大写
   - 策略名称标准化

3. **兼容性**:
   - 支持新旧版Quantumult X规则格式
   - 自动检测规则类型
   - 智能合并混合内容

### ⚙️ 使用方法

1. **Quantumult X配置**:
   ```ini
   [filter_remote]
   https://raw.githubusercontent.com/你的用户名/仓库/main/rules/filter_rules.conf
   
   [rewrite_remote]
   https://raw.githubusercontent.com/你的用户名/仓库/main/rules/rewrite_rules.conf