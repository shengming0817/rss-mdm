use crate::{Error, Expression, Operator, Result};
type Expr = Expression<String, String>;
pub fn parse(input: &str) -> Result<Expr> {
    if input.len() > crate::MAX_FILTER_BYTES {
        return Err(Error::Budget);
    }
    let mut p = Parser {
        input,
        offset: 0,
        nodes: 0,
        set_items: 0,
    };
    let result = p.logical(0, 0)?;
    if p.offset != input.len() {
        return Err(Error::Invalid);
    }
    Ok(result)
}
struct Parser<'a> {
    input: &'a str,
    offset: usize,
    nodes: usize,
    set_items: usize,
}
impl Parser<'_> {
    fn rest(&self) -> &str {
        &self.input[self.offset..]
    }
    fn eat(&mut self, c: char) -> bool {
        if self.rest().starts_with(c) {
            self.offset += c.len_utf8();
            true
        } else {
            false
        }
    }
    fn node(&mut self) -> Result<()> {
        if self.nodes >= 128 {
            return Err(Error::Budget);
        }
        self.nodes += 1;
        Ok(())
    }
    fn logical(&mut self, precedence: u8, depth: usize) -> Result<Expr> {
        if depth > 16 {
            return Err(Error::Budget);
        }
        if precedence == 2 {
            return self.atom(depth);
        }
        let first = self.logical(precedence + 1, depth)?;
        let separator = if precedence == 0 { ',' } else { ';' };
        if !self.eat(separator) {
            return Ok(first);
        }
        self.node()?;
        let mut children = vec![first];
        loop {
            children.push(self.logical(precedence + 1, depth)?);
            if !self.eat(separator) {
                break;
            }
        }
        Ok(if precedence == 0 {
            Expr::Or(children)
        } else {
            Expr::And(children)
        })
    }
    fn atom(&mut self, depth: usize) -> Result<Expr> {
        if self.eat('(') {
            if depth == 16 {
                return Err(Error::Budget);
            }
            let inner = self.logical(0, depth + 1)?;
            if !self.eat(')') {
                return Err(Error::Invalid);
            }
            return Ok(inner);
        }
        self.node()?;
        let start = self.offset;
        while self
            .rest()
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || matches!(*b, b'_' | b'.'))
        {
            self.offset += 1;
        }
        if self.offset == start || self.offset - start > 128 {
            return Err(Error::Invalid);
        }
        let field = self.input[start..self.offset].to_owned();
        let (token, operator) = [
            ("==", Operator::Eq),
            ("!=", Operator::Ne),
            ("=lt=", Operator::Lt),
            ("=le=", Operator::Le),
            ("=gt=", Operator::Gt),
            ("=ge=", Operator::Ge),
            ("=in=", Operator::In),
            ("=out=", Operator::Out),
            ("=icontains=", Operator::Icontains),
            ("=contains=", Operator::Contains),
            ("=notcontains=", Operator::NotContains),
            ("=containsany=", Operator::ContainsAny),
            ("=containsall=", Operator::ContainsAll),
            ("=isnull=", Operator::IsNull),
            ("=isnotnull=", Operator::IsNotNull),
        ]
        .into_iter()
        .find(|(s, _)| self.rest().starts_with(s))
        .ok_or(Error::Invalid)?;
        self.offset += token.len();
        let mut values = Vec::new();
        if operator.set() {
            if !self.eat('(') {
                return Err(Error::Invalid);
            }
            loop {
                if values.len() >= 64 || self.set_items >= 256 {
                    return Err(Error::Budget);
                }
                self.set_items += 1;
                values.push(self.value()?);
                if self.eat(')') {
                    break;
                }
                if !self.eat(',') {
                    return Err(Error::Invalid);
                }
            }
        } else {
            values.push(self.value()?);
        }
        Ok(Expr::Compare {
            field,
            operator,
            values,
        })
    }
    fn value(&mut self) -> Result<String> {
        let quote = self
            .rest()
            .chars()
            .next()
            .filter(|c| matches!(c, '\'' | '"'));
        if let Some(q) = quote {
            self.eat(q);
        }
        let mut result = String::new();
        let mut closed = quote.is_none();
        while let Some(c) = self.rest().chars().next() {
            if quote == Some(c) {
                self.eat(c);
                closed = true;
                break;
            }
            if quote.is_none() && matches!(c, ',' | ';' | ')') {
                break;
            }
            self.offset += c.len_utf8();
            let c = if c == '\\' {
                let escaped = self.rest().chars().next().ok_or(Error::Invalid)?;
                if !matches!(escaped, '\\' | '\'' | '"' | ',' | ';' | '(' | ')') {
                    return Err(Error::Invalid);
                }
                self.offset += escaped.len_utf8();
                escaped
            } else {
                if quote.is_none()
                    && (c.is_whitespace() || matches!(c, '(' | '\'' | '"' | '=' | '!' | '<' | '>'))
                {
                    return Err(Error::Invalid);
                }
                c
            };
            if c.is_control() || (quote.is_none() && c == '*') {
                return Err(Error::Invalid);
            }
            if result.len() + c.len_utf8() > 1024 {
                return Err(Error::Budget);
            }
            result.push(c);
        }
        if !closed || (quote.is_none() && result.is_empty()) {
            return Err(Error::Invalid);
        }
        Ok(result)
    }
}
