package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	amqp "github.com/rabbitmq/amqp091-go"
)

// CaptchaTask описывает задание по решению капчи
type CaptchaTask struct {
	ID              int64  `json:"id"`
	CaptchaType     string `json:"captcha_type"`
	SiteKey         string `json:"sitekey"`
	TargetURL       string `json:"target_url"`
	CaptchaResponse string `json:"captcha_response,omitempty"`
}

var (
	// Храним задачи в памяти (для демонстрации)
	tasks         = make(map[int64]*CaptchaTask)
	tasksMutex    sync.Mutex
	taskIDCounter int64 = 0
)

var rabbitMQConn *amqp.Connection
var rabbitMQChannel *amqp.Channel

const queueName = "captcha_tasks"

func main() {
	var err error

	// Подключение к RabbitMQ
	rabbitMQConn, err = amqp.Dial("amqp://guest:guest@localhost:5672/")
	if err != nil {
		log.Fatalf("Не удалось подключиться к RabbitMQ: %v", err)
	}
	defer rabbitMQConn.Close()

	rabbitMQChannel, err = rabbitMQConn.Channel()
	if err != nil {
		log.Fatalf("Не удалось открыть канал RabbitMQ: %v", err)
	}
	defer rabbitMQChannel.Close()

	// Объявляем очередь
	_, err = rabbitMQChannel.QueueDeclare(
		queueName, // название очереди
		true,      // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		log.Fatalf("Не удалось объявить очередь: %v", err)
	}

	// Запускаем горутину для чтения задач из RabbitMQ и добавления в очередь
	go consumeTasks()

	// Инициализируем шаблонизатор HTML (шаблоны в папке views)
	engine := html.New("./views", ".html")
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// API для создания новой задачи
	app.Post("/api/task", func(c *fiber.Ctx) error {
		// Ожидаем JSON: { "sitekey": "...", "target_url": "..." }
		type RequestPayload struct {
			CaptchaType string `json:"captcha_type"`
			SiteKey     string `json:"sitekey"`
			TargetURL   string `json:"target_url"`
		}
		var payload RequestPayload
		if err := c.BodyParser(&payload); err != nil {
			return c.Status(400).SendString("Неверный формат запроса")
		}
		if payload.SiteKey == "" || payload.TargetURL == "" {
			return c.Status(400).SendString("Необходимы sitekey и target_url")
		}

		if payload.CaptchaType == "" {
			payload.CaptchaType = "hCaptcha"
		}

		// Создаём задачу с уникальным ID
		newID := atomic.AddInt64(&taskIDCounter, 1)
		task := &CaptchaTask{
			ID:          newID,
			CaptchaType: payload.CaptchaType,
			SiteKey:     payload.SiteKey,
			TargetURL:   payload.TargetURL,
		}

		// Сериализуем задачу и отправляем в RabbitMQ
		taskBytes, err := json.Marshal(task)
		if err != nil {
			return c.Status(500).SendString("Ошибка обработки задачи")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = rabbitMQChannel.PublishWithContext(ctx,
			"",        // exchange
			queueName, // routing key
			false,     // mandatory
			false,     // immediate
			amqp.Publishing{
				ContentType: "application/json",
				Body:        taskBytes,
			})
		if err != nil {
			return c.Status(500).SendString("Ошибка отправки в RabbitMQ")
		}

		// Добавляем задачу в локальную очередь
		tasksMutex.Lock()
		tasks[task.ID] = task
		tasksMutex.Unlock()

		return c.JSON(task)
	})

	// Главная страница: отображение очереди задач
	app.Get("/", func(c *fiber.Ctx) error {
		tasksMutex.Lock()
		defer tasksMutex.Unlock()
		return c.Render("index", fiber.Map{
			"Title": "Очередь задач капчи",
			"Tasks": tasks,
		}, "layout")
	})

	// Страница для решения капчи (оператор получает задание)
	app.Get("/captcha/:id", func(c *fiber.Ctx) error {
		idParam := c.Params("id")
		var taskID int64
		_, err := fmt.Sscan(idParam, &taskID)
		if err != nil {
			return c.Status(400).SendString("Неверный ID задачи")
		}
		tasksMutex.Lock()
		task, exists := tasks[taskID]
		tasksMutex.Unlock()
		if !exists {
			return c.Status(404).SendString("Задача не найдена")
		}
		return c.Render("captcha", fiber.Map{
			"Title": "Решите капчу",
			"Task":  task,
		}, "layout")
	})

	// Обработка отправленного решения капчи
	app.Post("/solve/:id", func(c *fiber.Ctx) error {
		// Extract and parse task ID
		idParam := c.Params("id")
		var taskID int64
		_, err := fmt.Sscan(idParam, &taskID)
		if err != nil {
			return c.Status(400).SendString("Неверный ID задачи")
		}

		// Get the task first
		tasksMutex.Lock()
		task, exists := tasks[taskID]
		tasksMutex.Unlock()

		if !exists {
			return c.Status(404).SendString("Задача не найдена")
		}

		// Check for the appropriate captcha response based on type
		var captchaResponse string
		if task.CaptchaType == "recaptcha" {
			captchaResponse = c.FormValue("g-recaptcha-response")
		} else {
			// Default to hCaptcha if not specified or any other type
			captchaResponse = c.FormValue("h-captcha-response")
		}

		if captchaResponse == "" {
			return c.Status(400).SendString("Необходимо решить капчу")
		}

		// Update the task with the response
		tasksMutex.Lock()
		task.CaptchaResponse = captchaResponse
		tasksMutex.Unlock()

		// Send result to the results queue
		taskBytes, err := json.Marshal(task)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			rabbitMQChannel.PublishWithContext(ctx,
				"",                // exchange
				"captcha_results", // routing key
				false,             // mandatory
				false,             // immediate
				amqp.Publishing{
					ContentType: "application/json",
					Body:        taskBytes,
				})
		}

		return c.SendString("Капча успешно решена!")
	})

	// Клиент может получить результат решения по ID
	app.Get("/result/:id", func(c *fiber.Ctx) error {
		idParam := c.Params("id")
		var taskID int64
		_, err := fmt.Sscan(idParam, &taskID)
		if err != nil {
			return c.Status(400).SendString("Неверный ID задачи")
		}
		tasksMutex.Lock()
		task, exists := tasks[taskID]
		tasksMutex.Unlock()
		if !exists {
			return c.Status(404).SendString("Задача не найдена")
		}
		if task.CaptchaResponse == "" {
			return c.SendString("Капча ещё не решена")
		}
		return c.JSON(task)
	})

	// Создаем страницу для последовательного решения задач
	app.Get("/solve-queue", func(c *fiber.Ctx) error {
		tasksMutex.Lock()
		count := len(tasks)
		tasksMutex.Unlock()

		return c.Render("solve-queue", fiber.Map{
			"Title": "Решение капч",
			"Count": count,
		}, "layout")
	})

	// API для получения следующей задачи для решения
	app.Get("/api/next-task", func(c *fiber.Ctx) error {
		tasksMutex.Lock()
		defer tasksMutex.Unlock()

		// Находим первую нерешенную задачу
		for _, task := range tasks {
			if task.CaptchaResponse == "" {
				return c.JSON(task)
			}
		}

		// Если нет нерешенных задач, возвращаем 404
		return c.Status(404).JSON(fiber.Map{
			"error": "Нет доступных задач",
		})
	})

	// API для получения количества задач в очереди
	app.Get("/api/queue-count", func(c *fiber.Ctx) error {
		tasksMutex.Lock()
		defer tasksMutex.Unlock()

		// Считаем количество нерешенных задач
		count := 0
		for _, task := range tasks {
			if task.CaptchaResponse == "" {
				count++
			}
		}

		return c.JSON(fiber.Map{
			"count": count,
		})
	})

	log.Println("Сервер запущен на http://localhost:3003")
	log.Fatal(app.Listen(":3005"))
}

// consumeTasks читает сообщения из RabbitMQ и добавляет задачи в локальную очередь
func consumeTasks() {
	msgs, err := rabbitMQChannel.Consume(
		queueName, // queue
		"",        // consumer
		true,      // auto-ack
		false,     // exclusive
		false,     // no-local
		false,     // no-wait
		nil,       // args
	)
	if err != nil {
		log.Fatalf("Не удалось зарегистрировать потребителя: %v", err)
	}

	for msg := range msgs {
		var task CaptchaTask
		if err := json.Unmarshal(msg.Body, &task); err != nil {
			log.Println("Ошибка декодирования сообщения:", err)
			continue
		}
		tasksMutex.Lock()
		tasks[task.ID] = &task
		tasksMutex.Unlock()
		log.Printf("Задача получена из RabbitMQ: %+v\n", task)
	}
}
