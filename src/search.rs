//! BM25 ranking over tool names, descriptions and parameter names

use std::collections::HashMap;

const K1: f64 = 1.2;
const B: f64 = 0.75;
/// Repetitions that make a name or parameter hit count more than prose
const NAME_WEIGHT: u32 = 3;
const PARAM_WEIGHT: u32 = 2;
/// Credit for a query term that only prefixes an indexed term
const PREFIX_CREDIT: f64 = 0.5;

/// The text of one tool that search looks at
#[derive(Debug, Clone, Copy)]
pub struct SearchText<'a> {
    /// Namespaced tool name
    pub name: &'a str,
    /// Full description
    pub description: &'a str,
    /// Parameter names
    pub params: &'a [String],
}

#[derive(Debug)]
struct Document {
    terms: HashMap<String, u32>,
    length: u32,
}

/// An immutable BM25 index; document ids are positions in the build input
#[derive(Debug, Default)]
pub struct SearchIndex {
    documents: Vec<Document>,
    document_frequency: HashMap<String, usize>,
    average_length: f64,
}

impl SearchIndex {
    /// Indexes the given tools
    pub fn build<'a>(texts: impl IntoIterator<Item = SearchText<'a>>) -> Self {
        let mut documents = Vec::new();
        let mut document_frequency: HashMap<String, usize> = HashMap::new();

        for text in texts {
            let mut terms: HashMap<String, u32> = HashMap::new();
            let mut length = 0;
            let mut add = |tokens: Vec<String>, weight: u32| {
                for token in tokens {
                    *terms.entry(token).or_default() += weight;
                    length += weight;
                }
            };
            add(tokenize(text.name), NAME_WEIGHT);
            add(tokenize(text.description), 1);
            for param in text.params {
                add(tokenize(param), PARAM_WEIGHT);
            }

            for term in terms.keys() {
                *document_frequency.entry(term.clone()).or_default() += 1;
            }
            documents.push(Document { terms, length });
        }

        let total: u32 = documents.iter().map(|document| document.length).sum();
        let average_length = if documents.is_empty() {
            0.0
        } else {
            f64::from(total) / documents.len() as f64
        };

        Self {
            documents,
            document_frequency,
            average_length,
        }
    }

    /// Returns `(document id, score)` pairs, best first, limited to `limit`
    pub fn query(&self, query: &str, limit: usize) -> Vec<(usize, f64)> {
        let query_terms = tokenize(query);
        if query_terms.is_empty() || self.documents.is_empty() {
            return Vec::new();
        }

        let count = self.documents.len() as f64;
        let mut scores = vec![0.0_f64; self.documents.len()];

        for query_term in &query_terms {
            for (term, frequency) in &self.document_frequency {
                let credit = if term == query_term {
                    1.0
                } else if query_term.len() >= 3 && term.starts_with(query_term.as_str()) {
                    PREFIX_CREDIT
                } else {
                    continue;
                };
                let idf =
                    (1.0 + (count - *frequency as f64 + 0.5) / (*frequency as f64 + 0.5)).ln();

                for (score, document) in scores.iter_mut().zip(&self.documents) {
                    let Some(occurrences) = document.terms.get(term) else {
                        continue;
                    };
                    let occurrences = f64::from(*occurrences);
                    let norm =
                        1.0 - B + B * f64::from(document.length) / self.average_length.max(1.0);

                    *score += credit * idf * occurrences * (K1 + 1.0) / (occurrences + K1 * norm);
                }
            }
        }

        let mut ranked: Vec<(usize, f64)> = scores
            .into_iter()
            .enumerate()
            .filter(|(_, score)| *score > 0.0)
            .collect();
        ranked.sort_by(|left, right| right.1.total_cmp(&left.1).then(left.0.cmp(&right.0)));
        ranked.truncate(limit);

        ranked
    }
}

/// Lowercases and splits on punctuation and camelCase boundaries, with a
/// crude plural strip so `docs` finds `doc`
fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;

    let mut flush = |current: &mut String| {
        if !current.is_empty() {
            tokens.push(stem(&std::mem::take(current)));
        }
    };

    for character in text.chars() {
        if !character.is_alphanumeric() {
            flush(&mut current);
            previous_lower = false;
            continue;
        }
        if character.is_uppercase() && previous_lower {
            flush(&mut current);
        }
        previous_lower = character.is_lowercase() || character.is_numeric();
        current.extend(character.to_lowercase());
    }
    flush(&mut current);

    tokens
}

fn stem(token: &str) -> String {
    match token.strip_suffix('s') {
        Some(stem) if stem.len() >= 3 && !stem.ends_with('s') => stem.to_owned(),
        _ => token.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_matches_outrank_description_mentions() {
        let params = vec!["query".to_owned()];
        let none: Vec<String> = Vec::new();
        let index = SearchIndex::build([
            SearchText {
                name: "docs_searchDocs",
                description: "Find pages",
                params: &params,
            },
            SearchText {
                name: "mail_send",
                description: "Send mail; can also search docs",
                params: &none,
            },
            SearchText {
                name: "calc_add",
                description: "Add numbers",
                params: &none,
            },
        ]);

        let ranked = index.query("search docs", 5);

        assert_eq!(ranked.first().map(|hit| hit.0), Some(0));
        assert!(ranked.iter().all(|hit| hit.0 != 2));
    }
}
