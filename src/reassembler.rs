use pdu::*;
use std::collections::HashMap;
use std::rc::Weak;

struct Reassembler {
    //delayed: HashMap<&'a u32, TcpPdu<'a>>,
    listener: Weak<dyn Listener>,
}

struct Event;

trait Listener {
    fn notify(&self, event: &Event);
}

struct MyListener;

impl Listener for MyListener {
    fn notify(&self, _event: &Event) {
        println!("received event!!!");
    }
}

impl Reassembler {
    pub fn add(&self, packet: TcpPdu) {
        match self.listener.upgrade() {
            Some(listener) => listener.notify(&Event),
            None => println!("error reference dropped"),
        }
    }
    pub fn init(&mut self, listener: Weak<Listener>) {
        self.listener = listener;
    }
    pub fn dispatch(&self, event: &Event) {
        match self.listener.upgrade() {
            Some(l) => l.notify(event),
            None => println!("no listener"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::reassembler::Event;
    use crate::reassembler::Listener;
    use crate::reassembler::MyListener;
    use crate::reassembler::Reassembler;
    use std::rc::Rc;
    #[test]
    fn test_listener() {
        let rc: Rc<dyn Listener> = Rc::new(MyListener {});
        let r = Reassembler {
            listener: Rc::downgrade(&rc),
        };
        println!("===test_listener===");
        r.dispatch(&Event {});
        //r.init(m);
    }
}

// TODO: how to deal with wrapping sequence numbers
