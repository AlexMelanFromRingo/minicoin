//! Сериализация: как структуры превращаются в байты.
//!
//! Правило одно: числа пишутся в little-endian фиксированной ширины,
//! массивы байтов как есть, перед списком стоит его длина. Библиотек
//! здесь нет намеренно: формат байтов — часть протокола. Хеш блока и
//! транзакции считается от этих байтов, поэтому все узлы обязаны
//! получать их одинаково. Описание формата — в PROTOCOL.md.

#[derive(Default)]
pub struct Writer {
    pub bytes: Vec<u8>,
}

impl Writer {
    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }
    pub fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    pub fn raw(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }
}

/// Читает байты по порядку. Любая нехватка данных — ошибка, а не паника:
/// байты приходят из сети, и доверять им нельзя.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn raw(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.data.len() - self.pos < len {
            return Err("неожиданный конец данных".into());
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.raw(N)?.try_into().expect("длина совпадает"))
    }

    pub fn u8(&mut self) -> Result<u8, String> {
        Ok(self.raw(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    pub fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Лишние байты в конце — тоже ошибка: у одного объекта должно быть
    /// ровно одно байтовое представление.
    pub fn finish(&self) -> Result<(), String> {
        if self.pos != self.data.len() {
            return Err("лишние байты в конце".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_little_endian() {
        let mut w = Writer::default();
        w.u16(0x0102);
        w.u32(0x03040506);
        assert_eq!(w.bytes, [0x02, 0x01, 0x06, 0x05, 0x04, 0x03]);

        let mut r = Reader::new(&w.bytes);
        assert_eq!(r.u16(), Ok(0x0102));
        assert_eq!(r.u32(), Ok(0x03040506));
        assert!(r.finish().is_ok());
        assert!(r.u8().is_err());
    }
}
