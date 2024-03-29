" Vim syntax file
" Language:	Asterisk config file
" Maintainer:	tilghman
" Last Change:	2009 Mar 04 
" version 0.5
"
if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif

syn sync clear
syn sync fromstart

syn keyword     asteriskTodo            TODO contained
syn match       asteriskComment         ";.*" contains=asteriskTodo
syn match       asteriskContext         "\[.\{-}\]"
syn match       asteriskExten           "^\s*exten\s*=>\?\s*[^,]\+" contains=asteriskPattern
syn match       asteriskExten           "^\s*\(register\|channel\|ignorepat\|include\|\(no\)\?load\)\s*=>\?"
syn match       asteriskPattern         "_\(\[[[:alnum:]#*\-]\+\]\|[[:alnum:]#*]\)*\.\?" contained
syn match       asteriskPattern         "[^A-Za-z0-9,]\zs[[:alnum:]#*]\+\ze" contained
syn match       asteriskApp             ",\zs[a-zA-Z]\+\ze$"
syn match       asteriskApp             ",\zs[a-zA-Z]\+\ze("
" Digits plus oldlabel (newlabel)
syn match       asteriskPriority        ",\zs[[:digit:]]\+\(+[[:alpha:]][[:alnum:]_]*\)\?\(([[:alpha:]][[:alnum:]_]*)\)\?\ze," contains=asteriskLabel
" oldlabel plus digits (newlabel)
syn match       asteriskPriority        ",\zs[[:alpha:]][[:alnum:]_]*+[[:digit:]]\+\(([[:alpha:]][[:alnum:]_]*)\)\?\ze," contains=asteriskLabel
" s or n plus digits (newlabel)
syn match       asteriskPriority        ",\zs[sn]\(+[[:digit:]]\+\)\?\(([[:alpha:]][[:alnum:]_]*)\)\?\ze," contains=asteriskLabel
syn match       asteriskLabel           "(\zs[[:alpha:]][[:alnum:]]*\ze)" contained
syn match       asteriskError           "^\s*#\s*[[:alnum:]]*"
syn match       asteriskInclude         "^\s*#\s*\(include\|exec\)\s.*"
syn region      asteriskVar             matchgroup=asteriskVarStart start="\${" end="}" contains=asteriskVar,asteriskFunction,asteriskExp
syn match       asteriskVar             "\zs[[:alpha:]][[:alnum:]_]*\ze=" contains=asteriskVar,asteriskFunction,asteriskExp
syn match       asteriskFunction        "\${_\{0,2}[[:alpha:]][[:alnum:]_]*(.*)}" contains=asteriskVar,asteriskFunction,asteriskExp
syn match       asteriskFunction        "(\zs[[:alpha:]][[:alnum:]_]*(.\{-})\ze=" contains=asteriskVar,asteriskFunction,asteriskExp
syn region      asteriskExp             matchgroup=asteriskExpStart start="\$\[" end="]" contains=asteriskVar,asteriskFunction,asteriskExp
syn match       asteriskCodecsPermit    "^\s*\(allow\|disallow\)\s*=\s*.*$" contains=asteriskCodecs
syn match       asteriskCodecs          "\(g723\|gsm\|ulaw\|alaw\|g726\|adpcm\|slin\|lpc10\|g729\|speex\|ilbc\|all\s*$\)"
syn match       asteriskError           "^\(type\|auth\|permit\|deny\|bindaddr\|host\)\s*=.*$"
syn match       asteriskType            "^\zstype=\ze\<\(peer\|user\|friend\)\>$" contains=asteriskTypeType
syn match       asteriskTypeType        "\<\(peer\|user\|friend\)\>" contained
syn match       asteriskAuth            "^\zsauth\s*=\ze\s*\<\(md5\|rsa\|plaintext\)\>$" contains=asteriskAuthType
syn match       asteriskAuthType        "\<\(md5\|rsa\|plaintext\)\>" contained
syn match       asteriskAuth            "^\zs\(secret\|inkeys\|outkey\)\s*=\ze.*$"
syn match       asteriskAuth            "^\(permit\|deny\)\s*=\s*\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/\d\{1,3}\(\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\)\?\s*$" contains=asteriskIPRange
syn match       asteriskIPRange         "\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}" contained
syn match       asteriskIP              "\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}" contained
syn match       asteriskHostname        "\([[:alnum:]\-]*\.\)\+[[:alpha:]]\{2,10}" contained
syn match       asteriskPort            "\d\{1,5}" contained
syn match       asteriskSetting         "^\(tcp\|tls\)\?bindaddr\s*=\s*\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}$" contains=asteriskIP
syn match       asteriskError           "port\s*=.*$"
syn match       asteriskSetting         "^\(bind\)\?port\s*=\s*\d\{1,5}\s*$" contains=asteriskPort
syn match       asteriskSetting         "^host\s*=\s*\(dynamic\|\(\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\)\|\([[:alnum:]\-]*\.\)\+[[:alpha:]]\{2,10}\)" contains=asteriskIP,asteriskHostname
syn match		asteriskError			"[[:space:]]$"

" Define the default highlighting.
" For version 5.7 and earlier: only when not done already
" For version 5.8 and later: only when an item doesn't have highlighting yet
if version >= 508 || !exists("did_conf_syntax_inits")
  if version < 508
    let did_conf_syntax_inits = 1
    command -nargs=+ HiLink hi link <args>
  else
    command -nargs=+ HiLink hi def link <args>
  endif

  HiLink        asteriskComment         Comment
  HiLink        asteriskExten           String
  HiLink        asteriskContext         Preproc
  HiLink        asteriskPattern         Type
  HiLink        asteriskApp             Statement
  HiLink        asteriskInclude         Preproc
  HiLink        asteriskPriority        Preproc
  HiLink        asteriskLabel           Type
  HiLink        asteriskVar             String
  HiLink        asteriskVarStart        String
  HiLink        asteriskFunction        Function
  HiLink        asteriskExp             Type
  HiLink        asteriskExpStart        Type
  HiLink        asteriskCodecsPermit    Preproc
  HiLink        asteriskCodecs          String
  HiLink        asteriskType            Statement
  HiLink        asteriskTypeType        Type
  HiLink        asteriskAuth            String
  HiLink        asteriskAuthType        Type
  HiLink        asteriskIPRange         Identifier
  HiLink        asteriskIP              Identifier
  HiLink        asteriskPort            Identifier
  HiLink        asteriskHostname        Identifier
  HiLink        asteriskSetting         Statement
  HiLink        asteriskError           Error
 delcommand HiLink
endif
let b:current_syntax = "asterisk" 
" vim: ts=8 sw=2

