use std::{fmt::Display, net::SocketAddrV4, ops::Deref};

use pyo3::prelude::*;
use stream_reassembly::reassembler::*;

#[pyclass]
struct Reass {
    iter: stream_reassembly::reassembler::Reassembler,
}

#[pymethods]
impl Reass {
    #[new]
    fn new(file: &str, filter: Option<&str>) -> Self {
        Reass {
            iter: stream_reassembly::PcapReassembler::read_file(file, filter),
        }
    }
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }
    fn __next__(mut slf: PyRefMut<'_, Self>) -> Option<PyObject> {
        let res = match slf.iter.next() {
            Some(item) => {
                let res = Python::with_gil(|py| {
                    let key = PyFlowKey {
                        src: PySockAddrV4(item.0.src),
                        dst: PySockAddrV4(item.0.dst),
                    }
                    .into_py(py);
                    let data = item.1.into_py(py);
                    let overlap = item
                        .2
                        .into_iter()
                        .map(|i| PyInconsistency(i))
                        .collect::<Vec<PyInconsistency>>()
                        .into_py(py);
                    (key, data, overlap).into_py(py)
                });
                Some(res)
            }
            None => None,
        };
        res
    }
}

#[pymodule]
fn py_stream_reassembly(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<Reass>()?;
    Ok(())
}

// conversion stuff below

#[pyclass]
struct PyFlowKey {
    #[pyo3(get)]
    src: PySockAddrV4,
    #[pyo3(get)]
    dst: PySockAddrV4,
}

#[derive(Clone, Debug)]
struct PySockAddrV4(SocketAddrV4);

impl Deref for PySockAddrV4 {
    type Target = SocketAddrV4;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoPy<PyObject> for PySockAddrV4 {
    fn into_py(self, py: Python<'_>) -> PyObject {
        (self.ip().to_string(), self.port()).into_py(py)
    }
}

#[pyclass]
struct PyInconsistency(Inconsistency);

impl Display for PyInconsistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {}, {})", self.0.seq, self.0.orig, self.0.new)
    }
}

#[pymethods]
impl PyInconsistency {
    #[getter]
    fn seq(&self) -> PyResult<u32> {
        Ok(self.0.seq)
    }
    #[getter]
    fn new(&self) -> PyResult<u8> {
        Ok(self.0.new)
    }
    #[getter]
    fn orig(&self) -> PyResult<u8> {
        Ok(self.0.orig)
    }
    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("{}", self))
    }
}
