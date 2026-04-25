import { PrismaClient, HoneypotType, HoneypotStatus } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  await prisma.honeypot.upsert({
    where: { publicPort: 2222 },
    update: {},
    create: {
      name: "SSH Honeypot Alpha",
      type: HoneypotType.SSH,
      status: HoneypotStatus.STOPPED,
      publicPort: 2222,
      dockerService: "cowrie",
      configJson: {
        hostname: "ubuntu-server",
        version: "OpenSSH_8.9p1",
        osRelease: "Ubuntu 22.04.3 LTS",
        fakeUsers: ["root", "admin", "ubuntu"],
        interactiveShell: false,
      },
    },
  });

  console.log("Seed complete");
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
