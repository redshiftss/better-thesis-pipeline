use std::{
    io::{self, Write},
    process::Command,
    thread,
    time::Duration,
};

const FUFF_WORDLIST: &str = "~/pkg/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt";

fn main() {
    start_falco();
    for i in 1..500 {
        process_batch(i);
    }
}

fn process_batch(pagenum: u32) {
    let imgs : Vec<MyImage> = aggregate_and_pull_images(pagenum)
        .into_iter()
        .filter(|x| x.name != "falcosecurity/falco-no-driver:latest")
        .collect();
    println!("images: {:?}", imgs);
    for img in imgs {
        process_image(img);
    }
    cleanup(pagenum);
}

fn cleanup(pagenum: u32) {
    Command::new("bash")
        .arg("-c")
        .arg("docker stop $(docker ps -a -q)")
        .output()
        .expect("failed to clean up");
    Command::new("bash")
        .arg("-c")
        .arg("docker rm $(docker ps -a -q)")
        .output()
        .expect("failed to clean up");
    Command::new("bash")
        .arg("-c")
        .arg("docker image prune -a -f")
        .output()
        .expect("failed to clean up");
}

fn process_image(image: MyImage) {
    start_ffuf(image.clone());
    start_wapiti(image);
}

#[derive(Debug, Clone)]
struct MyImage {
    name: String,
    ips: Vec<String>,
}

fn aggregate_and_pull_images(pagenum: u32) -> Vec<MyImage> {
    // ---- make the HTTP call to DockerHub ------

    let body: serde_json::Value = ureq::get(&format!(
        "https://hub.docker.com/api/content/v1/products/search?page={}&page_size=5&q=",
        pagenum
    ))
    .set("Search-Version", "v3")
    .call()
    .unwrap()
    .into_json()
    .unwrap();

    let mut res = Vec::new();

    // ---- extract image names from DockerHub and spin up the containers ------

    for v in body["summaries"].as_array().unwrap() {
        res.push(format!("{}", v["name"].as_str().unwrap().clone()))
    }

    for image in res {
        Command::new("bash")
            .arg("-c")
            .arg(format!("docker pull {}", image))
            .output()
            .expect("failed to pull image");

        Command::new("bash")
            .arg("-c")
            .arg(format!("docker run -d -P {}", image))
            .output()
            .expect("failed to run image");
        println!("finished pulling images...");
    }

    // ---- connect the image names to the TCP ports they're using ------

    thread::sleep(Duration::from_secs(1));

    let output = Command::new("bash")
        .arg("-c")
        .arg("docker ps --format \"{{.Image}} {{.Ports}}\" | awk -F \'->\' \'{print $1}\'")
        .output()
        .expect("failed to aggregate ports");

    let mut imgs = Vec::new();

    let str = String::from_utf8(output.stdout).unwrap();

    // ---- do some string magics ------

    let lines = str.split("\n");

    for line in lines {
        let tokens = line.split(" ").collect::<Vec<&str>>();
        let name = tokens[0];
        let mut ips = Vec::new();
        let mut i = 1;

        while i < tokens.len() {
            ips.push(tokens[i].to_string());
            i += 1;
        }
        if name != "" {
            imgs.push(MyImage {
                name: name.to_string(),
                ips: ips,
            })
        }
    }
    return imgs;
}

fn start_ffuf(image: MyImage) {
    println!("starting ffuf...");
    for i in 0..image.ips.len() {
        let filename = format!("ffuf/{}_{}.json", image.name, i);
        Command::new("bash")
            .arg("-c")
            //fuzz every IP associated with this address and output results to json
            .arg(format!(
                "ffuf -w {} -u {}/FUZZ -o {} -of json",
                FUFF_WORDLIST, image.ips[i], filename
            ))
            .output()
            .expect("failed to fuzz IP address");
    }
}

fn start_falco() {
    //hmmmmmmm annoying, figure out
    // let filename = format!("/falco/falco_page_{}.json", pagenum);
    println!("starting falco...");
    thread::spawn(|| {
        Command::new("bash")
            .arg("-c")
            .arg(format!(
                "docker run --rm \
                    --privileged \
                    -v /var/run/docker.sock:/host/var/run/docker.sock \
                    -v /proc:/host/proc:ro \
                    -v $(pwd)/falco:/falco \
                    falcosecurity/falco-no-driver:latest \
                        falco \
                            --modern-bpf \
                            -c falco/falco.yaml"
            ))
            .output()
            .expect("Failed to start falco");
    });
}

fn start_wapiti(image: MyImage) {
    for i in 0..image.ips.len() {
        let filename = format!("wapiti/{}_{}.json", image.name, i);
        println!("running wapiti...");
        Command::new("bash")
            .arg("-c")
            //fuzz every IP associated with this address and output results to json
            .arg(format!(
                "wapiti -u http://{} -f json -o {}",
                image.ips[i], filename
            ))
            .output()
            .expect("failed to run wapiti on the image");
    }
}
