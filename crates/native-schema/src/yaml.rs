//! A source graph, rather than an expanded YAML tree: Apple schema has recursive anchors.
use std::collections::BTreeMap;
use yaml_rust2::parser::{Event, EventReceiver, Parser};

#[derive(Debug)]
pub enum Node {
    Scalar(String),
    Sequence(Vec<usize>),
    Mapping(BTreeMap<String, usize>),
}

#[derive(Default, Debug)]
pub struct Document {
    nodes: Vec<Node>,
    root: Option<usize>,
    stack: Vec<(usize, Option<String>)>,
    anchors: BTreeMap<usize, usize>,
    failure: Option<String>,
    documents: usize,
}

impl Document {
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.len() > 16 * 1024 * 1024 {
            return Err("schema source exceeds size limit".into());
        }
        let mut result = Self::default();
        Parser::new_from_str(input)
            .load(&mut result, true)
            .map_err(|e| e.to_string())?;
        if let Some(error) = result.failure.take() {
            return Err(error);
        }
        if result.documents != 1 || result.root.is_none() || !result.stack.is_empty() {
            return Err("expected one complete schema document".into());
        }
        Ok(result)
    }

    pub fn root(&self) -> usize {
        self.root.expect("validated document root")
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn get(&self, node: usize, key: &str) -> Option<usize> {
        match self.nodes.get(node)? {
            Node::Mapping(values) => values.get(key).copied(),
            _ => None,
        }
    }

    pub fn text(&self, node: usize) -> Result<&str, String> {
        match self.nodes.get(node) {
            Some(Node::Scalar(value)) => Ok(value),
            _ => Err("expected scalar".into()),
        }
    }

    pub fn sequence(&self, node: usize) -> Result<&[usize], String> {
        match self.nodes.get(node) {
            Some(Node::Sequence(values)) => Ok(values),
            _ => Err("expected sequence".into()),
        }
    }

    pub fn mapping(&self, node: usize) -> Result<&BTreeMap<String, usize>, String> {
        match self.nodes.get(node) {
            Some(Node::Mapping(values)) => Ok(values),
            _ => Err("expected mapping".into()),
        }
    }

    pub fn optional_text(&self, node: usize, key: &str) -> Result<Option<&str>, String> {
        self.get(node, key).map(|id| self.text(id)).transpose()
    }

    fn insert(&mut self, node: Node, anchor: usize) -> Result<usize, String> {
        if self.nodes.len() >= 200_000 || self.stack.len() >= 128 {
            return Err("schema source exceeds structure limit".into());
        }
        let id = self.nodes.len();
        self.nodes.push(node);
        if anchor != 0 && self.anchors.insert(anchor, id).is_some() {
            return Err("duplicate anchor".into());
        }
        self.attach(id)?;
        Ok(id)
    }

    fn attach(&mut self, id: usize) -> Result<(), String> {
        let scalar = match &self.nodes[id] {
            Node::Scalar(s) => Some(s.clone()),
            _ => None,
        };
        match self.stack.last_mut() {
            None if self.root.replace(id).is_some() => Err("multiple roots".into()),
            None => Ok(()),
            Some((parent, pending)) => match &mut self.nodes[*parent] {
                Node::Sequence(items) => {
                    items.push(id);
                    Ok(())
                }
                Node::Mapping(items) => {
                    if let Some(key) = pending.take() {
                        if items.insert(key, id).is_some() {
                            return Err("duplicate mapping key".into());
                        }
                    } else {
                        *pending = Some(scalar.ok_or("non-scalar mapping key")?);
                    }
                    Ok(())
                }
                Node::Scalar(_) => Err("scalar cannot contain children".into()),
            },
        }
    }

    fn event(&mut self, event: Event) -> Result<(), String> {
        match event {
            Event::DocumentStart => self.documents += 1,
            Event::Scalar(text, _, anchor, None) => {
                self.insert(Node::Scalar(text), anchor)?;
            }
            Event::SequenceStart(anchor, None) => {
                let id = self.insert(Node::Sequence(Vec::new()), anchor)?;
                self.stack.push((id, None));
            }
            Event::MappingStart(anchor, None) => {
                let id = self.insert(Node::Mapping(BTreeMap::new()), anchor)?;
                self.stack.push((id, None));
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let (_, pending) = self.stack.pop().ok_or("unbalanced collection")?;
                if pending.is_some() {
                    return Err("mapping has no value".into());
                }
            }
            Event::Alias(anchor) => {
                let id = *self.anchors.get(&anchor).ok_or("unresolved alias")?;
                self.attach(id)?;
            }
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
            _ => return Err("unsupported explicit YAML tag".into()),
        }
        Ok(())
    }
}

impl EventReceiver for Document {
    fn on_event(&mut self, event: Event) {
        if self.failure.is_none() {
            self.failure = self.event(event).err();
        }
    }
}
