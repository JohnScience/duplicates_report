use std::{
    env::current_dir,
    fs::File,
    io::{stdin, stdout, Read, Write},
    path::{Path, PathBuf},
    borrow::Cow,
    hash::{Hash, Hasher}, time::Duration,
};
use walkdir::WalkDir;
use sysinfo::{System, SystemExt};
use fxhash::{FxHasher, FxHashMap};
use crossterm::{ExecutableCommand, terminal, cursor, QueueableCommand};

struct TerminalStateDuringHashing {
    pub stdout: std::io::Stdout,
    pub line_start: u16,
    pub column_start: u16,
}

struct FilesForHashing(FxHashMap<PathBuf, u64>);

struct FilesHashesPairs(FxHashMap<PathBuf, u64>);

struct FilenameCollisions<'a> (FxHashMap<Cow<'a, str>, Vec<(&'a PathBuf, &'a u64)>>);

impl TerminalStateDuringHashing {
    fn new() -> Self {
        let mut stdout = stdout();
        let (line_start, column_start) = cursor::position().unwrap();
        print!("Files hashed: ");
        stdout.execute(cursor::SavePosition).unwrap();

        Self { stdout, line_start, column_start }
    }

    fn clear_from_section_start(&mut self) {
        self.stdout.execute(cursor::MoveTo(self.line_start, self.column_start)).unwrap()
            .execute(terminal::Clear(terminal::ClearType::FromCursorDown)).unwrap();
    }

    fn restore(&mut self) {
        self.clear_from_section_start();
        print!("Files hashed: ");
    }

    fn notify_about_file_opening_err(&mut self, path: &Path, e: &std::io::Error) {
        self.clear_from_section_start();
        println!("Error while opening file {}: {}", path.display(), e);
        
    }

    fn update_files_hashed(&mut self, files_hashed: usize) -> () {
        print!("{files_hashed}");
        self.stdout.flush().unwrap();
    }
}

impl FilesForHashing {
    fn heuristic_buf_size_in_kb(_available_mem_in_kb: u64) -> usize {
        // match available_mem_in_kb {
        //     0..=64 => 8,
        //     _ => std::cmp::max(8, (available_mem_in_kb - 64).try_into().unwrap()),
        // }
        128
    }

    fn heuristic_buf_capacity(available_mem_in_kb: u64) -> usize {
        Self::heuristic_buf_size_in_kb(available_mem_in_kb) * 1024
    }

    pub fn try_new(path: &Path) -> Option<Self> {
        if !path.is_dir() { None } else {

            let mut stdout = stdout();

            print!("Files found in the directory and its subdirectories: ");
            stdout.execute(cursor::SavePosition).unwrap();
            print!("0");

            let files_hashes_pairs = WalkDir::new(path)
                .into_iter()
                .filter_map(|res_entry| res_entry.ok())
                .filter(|e| e.file_type().is_file())
                .enumerate()
                // String as the FxHashMap Value type-argument will be used later to store the hashes of files
                .fold(FxHashMap::<PathBuf, u64>::default(), |mut files_hashes_pairs, (i, entry)| {
                    stdout.queue(cursor::RestorePosition).unwrap()
                        .queue(terminal::Clear(terminal::ClearType::FromCursorDown)).unwrap();
                    print!("{files_found}", files_found = i + 1);
                    stdout.flush().unwrap();
                    files_hashes_pairs.insert(entry.path().to_path_buf(), u64::default());
                    files_hashes_pairs
                });

            println!();

            Some(FilesForHashing(files_hashes_pairs))
        }
    }

    // Tries to open file until it succeedes. The name is inspired by spin lock
    fn spin_open_file(ts: &mut TerminalStateDuringHashing, path: &Path) -> File {
        let mut is_errorless = true;
            
        loop {
            match File::open(path) {
                Ok(file) => {
                    if !is_errorless { ts.restore(); };
                    return file
                },
                Err(e) => {
                    if is_errorless { is_errorless = false; };
                    ts.notify_about_file_opening_err(path, &e);
                    std::thread::sleep(Duration::from_secs(10));
                }
            }
        }
    }

    // Tries to read file chunk until it succeeds. The name is inspired by spin lock
    fn spin_read_file_chunk(ts: &mut TerminalStateDuringHashing, path: &Path, file: &mut File, buf: &mut Vec<u8>) -> usize {
        let mut is_errorless = true;
        loop {
            let reading_res = std::io::Read::by_ref(file)
                .take(buf.capacity() as u64)
                .read_to_end(buf);
            
            match reading_res {
                Ok(bytes_read) => {
                    if !is_errorless { ts.restore(); };
                    return bytes_read
                },
                Err(e) => {
                    is_errorless = false;
                    ts.notify_about_file_opening_err(path, &e);
                    std::thread::sleep(Duration::from_secs(10));
                    continue;
                }
            }
        }
    }

    pub fn into_files_hashes_pairs(mut self, available_mem_in_kb: u64) -> FilesHashesPairs {
        let mut ts = TerminalStateDuringHashing::new();

        self.0.iter_mut().enumerate().for_each(|(i, (path, hash))| {
            ts.restore();
            ts.update_files_hashed(i);
            
            let mut file = Self::spin_open_file(&mut ts, path);
            let mut hasher = FxHasher::default();
            let contents_buf_capacity = Self::heuristic_buf_capacity(available_mem_in_kb);
            let mut contents_buf = Vec::<u8>::with_capacity(contents_buf_capacity);

            loop {
                let bytes_read = Self::spin_read_file_chunk(&mut ts, path, &mut file, &mut contents_buf);
                contents_buf.hash(&mut hasher);
                contents_buf.clear();
                if bytes_read == 0 { break; }
            }

            *hash = hasher.finish();
        });
        FilesHashesPairs(self.0)
    }
}

impl FilesHashesPairs {
    pub fn iter(&self) -> std::collections::hash_map::Iter<PathBuf, u64> {
        self.0.iter()
    }

    fn print(&self) {
        println!("Path/hash pairs:");
        for (path, hash) in self.iter() {
            println!("\t{}: {}", path.to_string_lossy(), hash);
        }
    }

    pub fn println(&self) {
        self.print();
        println!();
    }

    pub fn get_filename_collisions(&self) -> FilenameCollisions {
        let mut filename_collisions = FxHashMap::<Cow<str>, Vec<(&PathBuf, &u64)>>::default();

        for (path, hash) in self.iter() {
            let filename = path.file_name().unwrap().to_string_lossy();
            let collisions = filename_collisions
                .entry(filename)
                .or_insert(Vec::<(&PathBuf, &u64)>::new());
            collisions.push((path, hash));
        }

        filename_collisions.retain(|_, v| v.len() > 1);

        FilenameCollisions(filename_collisions)
    }
}

impl<'a> FilenameCollisions<'a> {
    pub fn iter(&self) -> std::collections::hash_map::Iter<Cow<str>, Vec<(&PathBuf, &u64)>> {
        self.0.iter()
    }

    pub fn print<W: Write>(&self, mut w: W) {
        write!(&mut w, "Filename collisions:\n").unwrap();
        for (filename, collisions) in self.iter() {
            write!(&mut w, "\t\"{}\":\n", filename).unwrap();
            for (path, hash) in collisions {
                write!(&mut w, "\t\t{}: {}\n", path.to_string_lossy(), hash).unwrap();
            }
        }
    }
}

fn trim_endline(s: &mut String) {
    if let Some('\n') = s.chars().next_back() {
        s.pop();
    }
    if let Some('\r') = s.chars().next_back() {
        s.pop();
    }
}

fn try_print_duplicates_report(path: &Path, available_mem_in_kb: u64) {
    let files_for_hashing = FilesForHashing::try_new(path)
        .expect("The path was expected to be leading to a directory");

    let files_hashes_pairs = files_for_hashing
        .into_files_hashes_pairs(available_mem_in_kb);

    files_hashes_pairs.println();

    let filename_collisions = files_hashes_pairs.get_filename_collisions();

    let report_path = Path::new("output.txt");
    let report = File::create(report_path).unwrap();
    filename_collisions.print(report);
}

fn main() {
    println!(
        "Current working directory is {}",
        current_dir().unwrap().to_string_lossy()
    );

    let sys = System::new_all();

    let available_mem_in_kb = sys.available_memory();
    let available_mem_in_b = available_mem_in_kb * 1024;

    println!(
        "Available memory: {} KB ({} B)",
        available_mem_in_kb,
        available_mem_in_b,
    );

    let mut dir_path_s_buf = String::new();

    println!("Please enter the path to the directory for which you would like to see the duplicates report:");
    print!("\t");
    let _ = stdout().flush();
    stdin()
        .read_line(&mut dir_path_s_buf)
        .expect("Did not enter a correct string");
    println!();

    trim_endline(&mut dir_path_s_buf);

    let path = Path::new(&dir_path_s_buf);

    try_print_duplicates_report(path, available_mem_in_kb);
}
