import { useMemo } from "react";
import { marked } from "marked";
import type { MarkedOptions } from "marked";

interface MarkdownProps {
  text: string;
  className?: string;
}

/**
 * Renders a bounded markdown string as safe HTML.
 *
 * marked is configured to ignore raw HTML so AI output (untrusted text)
 * cannot inject markup. Only inline and block text formatting is rendered:
 * headings, emphasis, lists, code spans, links, tables, and blockquotes.
 * Dangerous URL schemes are stripped from the rendered output as a second
 * line of defense.
 */
export function Markdown({ text, className }: MarkdownProps) {
  const html = useMemo(() => {
    let rendered = marked.parse(text ?? "", {
      pedantic: false,
      gfm: true,
      breaks: false,
    } as MarkedOptions) as string;

    // Strip dangerous URL schemes from href/src attributes so model output
    // cannot create script-executing links.
    rendered = rendered.replace(
      /(href|src)=["'](javascript|data|vbscript|file):[^"']*["']/gi,
      '$1=""'
    );
    return rendered;
  }, [text]);

  return (
    <div
      className={className ?? "markdown-body"}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
